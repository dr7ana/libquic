#pragma once

extern "C"
{
#include <event2/event.h>
#include <event2/thread.h>
}

#include <atomic>
#include <cstdint>
#include <future>
#include <memory>
#include <thread>

#include "context.hpp"
#include "crypto.hpp"
#include "utils.hpp"

namespace oxen::quic
{
    using Job = std::function<void()>;

    static void setup_libevent_logging();

    using loop_time = std::chrono::microseconds;
    using loop_ptr = std::shared_ptr<::event_base>;

    class Loop;

    struct EventHandler : public std::enable_shared_from_this<EventHandler>
    {
        friend class Loop;

      private:
        std::atomic<bool> _is_running{false};
        bool _is_stopped{false};
        event_ptr ev;
        timeval interval;
        std::function<void()> f;

        void start_event(
                const loop_ptr& _loop,
                loop_time _interval,
                std::function<void()> task,
                bool persist = true,
                bool start_immediately = true);

        EventHandler() = default;

      public:
        ~EventHandler();

        bool is_running() const { return _is_running and !_is_stopped; }

        bool is_paused() const { return !(_is_running or _is_stopped); }

        bool is_stopped() const { return _is_stopped; }

        bool start();
        bool pause();
        bool stop();
    };

    class Loop
    {
        friend class Network;

      protected:
        std::atomic<bool> running{false};
        std::shared_ptr<::event_base> ev_loop;
        std::optional<std::thread> loop_thread;
        std::thread::id loop_thread_id;

        event_ptr job_waker;
        std::queue<Job> job_queue;
        std::mutex job_queue_mutex;

        template <typename Callable>
        void add_oneshot_event(loop_time delay, Callable&& hook)
        {
            auto handler = make_handler();
            auto& h = *handler;

            h.start_event(
                    loop(),
                    delay,
                    [hdnlr = std::move(handler), func = std::forward<Callable>(hook)]() mutable {
                        func();
                        hdnlr.reset();
                    },
                    false);
        }

      public:
        Loop();
        Loop(std::shared_ptr<::event_base> loop_ptr, std::thread::id thread_id);

        virtual ~Loop();

        const std::shared_ptr<::event_base>& loop() const { return ev_loop; }

        bool in_event_loop() const { return std::this_thread::get_id() == loop_thread_id; }

        std::shared_ptr<EventHandler> make_handler();

        // Returns a pointer deleter that defers the actual destruction call to this network
        // object's event loop.
        template <typename T>
        auto loop_deleter()
        {
            return [this](T* ptr) { call([ptr] { delete ptr; }); };
        }

        // Returns a pointer deleter that defers invocation of a custom deleter to the event loop
        template <typename T, typename Callable>
        auto wrapped_deleter(Callable&& f)
        {
            return [this, func = std::forward<Callable>(f)](T* ptr) {
                return call_get([f = std::move(func), ptr]() { return f(ptr); });
            };
        }

        // Similar in concept to std::make_shared<T>, but it creates the shared pointer with a
        // custom deleter that dispatches actual object destruction to the network's event loop for
        // thread safety.
        template <typename T, typename... Args>
        std::shared_ptr<T> make_shared(Args&&... args)
        {
            auto* ptr = new T{std::forward<Args>(args)...};
            return std::shared_ptr<T>{ptr, loop_deleter<T>()};
        }

        // Similar to the above make_shared, but instead of forwarding arguments for the
        // construction of the object, it creates the shared_ptr from the already created object ptr
        // and wraps the object's deleter in a wrapped_deleter
        template <typename T, typename Callable>
        std::shared_ptr<T> shared_ptr(T* obj, Callable&& deleter)
        {
            return std::shared_ptr<T>(obj, wrapped_deleter<T>(std::forward<Callable>(deleter)));
        }

        template <typename Callable>
        void call(Callable&& f)
        {
            if (in_event_loop())
            {
                f();
            }
            else
            {
                call_soon(std::forward<Callable>(f));
            }
        }

        template <typename Callable, typename Ret = decltype(std::declval<Callable>()())>
        Ret call_get(Callable&& f)
        {
            if (in_event_loop())
            {
                return f();
            }

            std::promise<Ret> prom;
            auto fut = prom.get_future();

            call_soon([&f, &prom] {
                try
                {
                    if constexpr (!std::is_void_v<Ret>)
                        prom.set_value(f());
                    else
                    {
                        f();
                        prom.set_value();
                    }
                }
                catch (...)
                {
                    prom.set_exception(std::current_exception());
                }
            });

            return fut.get();
        }

        /** This overload of `call_every` will begin an indefinitely repeating object tied to the lifetime of `caller`.
            Prior to executing each iteration, the weak_ptr will be checked to ensure the calling object lifetime has
            persisted up to that point.
        */
        template <typename Callable>
        void call_every(loop_time interval, std::weak_ptr<void> caller, Callable&& f)
        {
            auto handler = make_handler();
            // grab the reference before giving ownership of the repeater to the lambda
            auto& h = *handler;

            h.start_event(
                    loop(),
                    interval,
                    [hndlr = std::move(handler), owner = std::move(caller), func = std::forward<Callable>(f)]() mutable {
                        if (auto ptr = owner.lock())
                            func();
                        else
                            hndlr.reset();
                    });
        }

        /** This overload of `call_every` will return an EventHandler object from which the application can start and stop
            the repeated event. It is NOT tied to the lifetime of the caller via a weak_ptr. If the application wants
            to defer start until explicitly calling EventHandler::start(), `start_immediately` should take a false boolean.
        */
        template <typename Callable>
        std::shared_ptr<EventHandler> call_every(loop_time interval, Callable&& f, bool start_immediately = true)
        {
            auto h = make_handler();

            h->start_event(loop(), interval, std::forward<Callable>(f), true, start_immediately);

            return h;
        }

        template <typename Callable>
        void call_later(loop_time delay, Callable&& hook)
        {
            if (in_event_loop())
            {
                add_oneshot_event(delay, std::forward<Callable>(hook));
            }
            else
            {
                call_soon([this, func = std::move(hook), target_time = get_timestamp<loop_time>() + delay]() mutable {
                    auto updated_delay = target_time - get_timestamp<loop_time>();

                    if (updated_delay <= 0us)
                        func();
                    else
                        add_oneshot_event(updated_delay, std::forward<Callable>(func));
                });
            }
        }

        template <typename Callable>
        void call_soon(Callable&& f)
        {
            {
                std::lock_guard lock{job_queue_mutex};
                job_queue.emplace(std::forward<Callable>(f));
            }

            event_active(job_waker.get(), 0, 0);
        }

        void shutdown(bool immediate = false);

      private:
        void setup_job_waker();

        void process_job_queue();
    };
}  //  namespace oxen::quic
