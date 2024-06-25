#pragma once

extern "C"
{
#include <event2/event.h>
#include <event2/thread.h>
}

#include <atomic>
#include <cstdint>
#include <forward_list>
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

    using loop_ptr = std::shared_ptr<::event_base>;

    class Loop;

    struct EventTrigger
    {
        friend class Loop;

      private:
        EventTrigger(
                const loop_ptr& _loop,
                std::chrono::microseconds _cooldown,
                std::function<void()> task,
                int _n,
                bool start_immediately = true);

      public:
        static std::shared_ptr<EventTrigger> make(
                const std::shared_ptr<Loop>& _loop,
                std::chrono::microseconds _cooldown,
                std::function<void()> task,
                int _n,
                bool start_immediately = true);

        // No move/copy/etc
        EventTrigger() = delete;
        EventTrigger(const EventTrigger&) = delete;
        EventTrigger(EventTrigger&&) = delete;
        EventTrigger& operator=(const EventTrigger&) = delete;
        EventTrigger& operator=(EventTrigger&&) = delete;

        ~EventTrigger();

        // Resumes iterative execution after successfully cooling down or being signalled to stop by the callback
        bool begin();

        // Called by the passed callback to signal that the iterative invocation should STOP
        void halt();

      private:
        // Invokes the function `f`, incrementing `::current` up to `n` before cooling down
        void fire();

        // Awaits further execution for `_cooldown` amount of time
        void cooldown();

        const int n;
        std::atomic<int> _current{0};

        event_ptr ev;
        const timeval _cooldown;
        const timeval _null_tv{};
        std::function<void()> f;

        std::atomic<bool> _is_cooling_down{false};
        std::atomic<bool> _is_iterating{false};

        // Internal boolean for the callback to signal execution should be stopped after the current iteration
        std::atomic<bool> _proceed{true};

      public:
        // Indicates the EventTrigger is invoking its callback `n` number of times. During one of these iterations,
        // the callback may signal termination of iteration by setting `::_proceed = false`
        bool is_iterating() const { return _is_iterating; }

        // Indicates the EventTrigger has just invoked its callback `n` number of times, and is now awaiting its next
        // attempt at execution (which will be in `::cooldown` amount of time)
        bool is_cooling_down() const { return _is_cooling_down; }
    };

    struct Ticker
    {
        friend class Loop;

      private:
        std::atomic<bool> _is_running{false};
        event_ptr ev;
        timeval interval;
        std::function<void()> f;

        void start_event(
                const loop_ptr& _loop,
                std::chrono::microseconds _interval,
                std::function<void()> task,
                bool persist = true,
                bool start_immediately = true);

        Ticker() = default;

      public:
        ~Ticker();

        bool is_running() const { return _is_running; }

        /** Starts the repeating event on the given interval on Ticker creation
            Returns:
                - true: event successfully started
                - false: event is already running, or failed to start the event
         */
        bool start();

        /** Stops the repeating event managed by Ticker
            Returns:
                - true: event successfully stopped
                - false: event is already stopped, or failed to stop the event
         */
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

        template <std::invocable Callable>
        void add_oneshot_event(std::chrono::microseconds delay, Callable hook)
        {
            auto handler = make_handler();
            auto& h = *handler;

            h.start_event(
                    loop(),
                    delay,
                    [hndlr = std::move(handler), func = std::move(hook)]() mutable {
                        auto h = std::move(hndlr);
                        func();
                        h.reset();
                    },
                    false);
        }

      private:
        std::list<std::weak_ptr<Ticker>> _tickers;

        void clear_old_tickers();

      public:
        Loop();
        Loop(std::shared_ptr<::event_base> loop_ptr, std::thread::id thread_id);

        virtual ~Loop();

        const std::shared_ptr<::event_base>& loop() const { return ev_loop; }

        bool in_event_loop() const { return std::this_thread::get_id() == loop_thread_id; }

        std::shared_ptr<Ticker> make_handler();

        // Returns a pointer deleter that defers the actual destruction call to this network
        // object's event loop.
        template <typename T>
        auto loop_deleter()
        {
            return [this](T* ptr) { call([ptr] { delete ptr; }); };
        }

        // Returns a pointer deleter that defers invocation of a custom deleter to the event loop
        template <typename T, std::invocable<T*> Callable>
        auto wrapped_deleter(Callable f)
        {
            return [this, func = std::move(f)](T* ptr) mutable {
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

        template <typename T, typename... Args>
        std::unique_ptr<T> make_unique(Args&&... args)
        {
            auto* ptr = new T{std::forward<Args>(args)...};
            return std::unique_ptr<T>{ptr, loop_deleter<T>()};
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
        void call_every(std::chrono::microseconds interval, std::weak_ptr<void> caller, Callable&& f)
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
        [[nodiscard]] std::shared_ptr<Ticker> call_every(
                std::chrono::microseconds interval, Callable&& f, bool start_immediately = true)
        {
            auto h = make_handler();

            h->start_event(loop(), interval, std::forward<Callable>(f), true, start_immediately);

            return h;
        }

        template <std::invocable Callable>
        void call_later(std::chrono::microseconds delay, Callable hook)
        {
            if (in_event_loop())
            {
                add_oneshot_event(delay, std::move(hook));
            }
            else
            {
                call_soon([this, func = std::move(hook), target_time = get_time() + delay]() mutable {
                    auto now = get_time();

                    if (now >= target_time)
                        func();
                    else
                        add_oneshot_event(
                                std::chrono::duration_cast<std::chrono::microseconds>(target_time - now), std::move(func));
                });
            }
        }

        template <std::invocable Callable>
        void call_soon(Callable f)
        {
            {
                std::lock_guard lock{job_queue_mutex};
                job_queue.emplace(std::move(f));
            }

            event_active(job_waker.get(), 0, 0);
        }

        void shutdown(bool immediate = false);

      private:
        void setup_job_waker();

        void process_job_queue();
    };
}  //  namespace oxen::quic
