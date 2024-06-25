#include "loop.hpp"

#include "internal.hpp"

namespace oxen::quic
{
    static auto ev_cat = log::Cat("ev-loop");

    static void setup_libevent_logging()
    {
        event_set_log_callback([](int severity, const char* msg) {
            switch (severity)
            {
                case _EVENT_LOG_ERR:
                    log::error(ev_cat, "{}", msg);
                    break;
                case _EVENT_LOG_WARN:
                    log::warning(ev_cat, "{}", msg);
                    break;
                case _EVENT_LOG_MSG:
                    log::info(ev_cat, "{}", msg);
                    break;
                case _EVENT_LOG_DEBUG:
                    log::debug(ev_cat, "{}", msg);
                    break;
            }
            std::abort();
        });
    }

    /** Static casting to `decltype(timeval::tv_{sec,usec})` makes sure that;
        - on linux
            .tv_sec is type __time_t
            .tv_usec is type __suseconds_t
        - on OSX    (https://developer.apple.com/documentation/kernel/timeval)
            .tv_sec is type __darwin_time_t
                - this is an annoying typedef of `time_t`
            .tv_usec is type __darwin_suseconds_t
                - this is an equally annoying typedef for `suseconds_t`
        Alas, yet again another mac idiosyncrasy...
     */
    timeval loop_time_to_timeval(std::chrono::microseconds t)
    {
        return timeval{
                .tv_sec = static_cast<decltype(timeval::tv_sec)>(t / 1s),
                .tv_usec = static_cast<decltype(timeval::tv_usec)>((t % 1s) / 1us)};
    }

    std::shared_ptr<EventTrigger> EventTrigger::make(
            const std::shared_ptr<Loop>& _loop,
            std::chrono::microseconds _cooldown,
            std::function<void()> task,
            int _n,
            bool start_immediately)
    {
        return _loop->template make_shared<EventTrigger>(_loop->loop(), _cooldown, std::move(task), _n, start_immediately);
    }

    EventTrigger::EventTrigger(
            const loop_ptr& _loop,
            std::chrono::microseconds _cooldown,
            std::function<void()> task,
            int _n,
            bool start_immediately) :
            n{_n}, _cooldown{loop_time_to_timeval(_cooldown)}, f{std::move(task)}
    {
        ev.reset(event_new(
                _loop.get(),
                -1,
                0,
                [](evutil_socket_t, short, void* s) {
                    try
                    {
                        auto* self = reinterpret_cast<EventTrigger*>(s);
                        assert(self);

                        if (not self->f)
                        {
                            log::critical(log_cat, "EventTrigger does not have a callback to execute!");
                            return;
                        }

                        if (self->_is_cooling_down)
                        {
                            log::critical(log_cat, "EventTrigger attempting to execute cooling down event!");
                            return;
                        }

                        if (not self->_proceed)
                        {
                            log::critical(log_cat, "EventTrigger attempting to execute finished event!");
                            return;
                        }

                        log::critical(log_cat, "EventTrigger executing callback...");
                        self->fire();
                    }
                    catch (const std::exception& e)
                    {
                        log::critical(log_cat, "EventTrigger caught exception: {}", e.what());
                    }
                },
                this));

        if (start_immediately)
        {
            auto rv = begin();
            log::debug(log_cat, "EventTrigger started {}successfully!", rv ? "" : "un");
        }
    }

    EventTrigger::~EventTrigger()
    {
        ev.reset();
        f = nullptr;
    }

    void EventTrigger::fire()
    {
        if (_current < n)
        {
            _current += 1;

            log::critical(log_cat, "Attempting callback {}/{} times!", _current.load(), n);
            f();
        }

        if (_current == n)
        {
            log::critical(log_cat, "Callback attempted {} times! Cooling down...", n);
            return cooldown();
        }

        event_del(ev.get());
        event_add(ev.get(), &_null_tv);
    }

    void EventTrigger::halt()
    {
        _is_cooling_down = false;
        _is_iterating = false;
        _proceed = false;

        auto rv = event_del(ev.get());
        log::critical(log_cat, "EventTrigger halted {}successfully!", rv == 0 ? "" : "un");
    }

    bool EventTrigger::begin()
    {
        _is_cooling_down = false;
        _is_iterating = true;
        _proceed = true;
        _current = 0;

        auto rv = event_add(ev.get(), &_null_tv);
        log::critical(log_cat, "EventTrigger begun {}successfully!", rv == 0 ? "" : "un");

        return rv == 0;
    }

    void EventTrigger::cooldown()
    {
        event_del(ev.get());

        _is_cooling_down = true;
        _is_iterating = false;

        auto rv = event_base_once(
                event_get_base(ev.get()),
                -1,
                EV_TIMEOUT,
                [](evutil_socket_t, short, void* s) {
                    try
                    {
                        auto* self = reinterpret_cast<EventTrigger*>(s);
                        assert(self);

                        if (not self->f)
                        {
                            log::critical(log_cat, "EventTrigger does not have a callback to execute!");
                            return;
                        }

                        if (not self->_is_cooling_down)
                        {
                            log::critical(log_cat, "EventTrigger attempting to resume when it is NOT cooling down!");
                            return;
                        }

                        if (not self->_proceed)
                        {
                            log::critical(log_cat, "EventTrigger attempting to resume when it is halted!");
                            return;
                        }

                        log::critical(log_cat, "EventTrigger resuming callback iteration...");
                        self->begin();
                    }
                    catch (const std::exception& e)
                    {
                        log::critical(log_cat, "EventTrigger caught exception: {}", e.what());
                    }
                },
                this,
                &_cooldown);

        log::critical(log_cat, "EventTrigger scheduled cooldown resume {}successfully!", rv == 0 ? "" : "un");
    }

    bool Ticker::start()
    {
        if (_is_running)
            return false;

        if (event_add(ev.get(), &interval) != 0)
        {
            log::critical(log_cat, "EventHandler failed to start repeating event!");
            return false;
        }

        _is_running = true;

        return true;
    }

    bool Ticker::stop()
    {
        if (not _is_running)
            return false;

        if (event_del(ev.get()) != 0)
        {
            log::critical(log_cat, "EventHandler failed to pause repeating event!");
            return false;
        }

        _is_running = false;

        return true;
    }

    void Ticker::start_event(
            const loop_ptr& _loop,
            std::chrono::microseconds _interval,
            std::function<void()> task,
            bool persist,
            bool start_immediately)
    {
        f = std::move(task);
        interval = loop_time_to_timeval(_interval);

        ev.reset(event_new(
                _loop.get(),
                -1,
                persist ? EV_PERSIST : 0,
                [](evutil_socket_t, short, void* s) {
                    try
                    {
                        auto* self = reinterpret_cast<Ticker*>(s);
                        // execute callback
                        self->f();
                    }
                    catch (const std::exception& e)
                    {
                        log::critical(log_cat, "EventHandler caught exception: {}", e.what());
                    }
                },
                this));

        if (start_immediately and not start())
            log::critical(log_cat, "Failed to immediately start event repeater!");
    }

    Ticker::~Ticker()
    {
        ev.reset();
        f = nullptr;
    }

    void Loop::clear_old_tickers()
    {
        for (auto itr = _tickers.begin(); itr != _tickers.end();)
        {
            if (itr->expired())
                itr = _tickers.erase(itr);
            else
                ++itr;
        }
    }

    std::shared_ptr<Ticker> Loop::make_handler()
    {
        clear_old_tickers();
        auto t = make_shared<Ticker>();
        _tickers.push_back(t);
        return t;
    }

    Loop::Loop(std::shared_ptr<::event_base> loop_ptr, std::thread::id thread_id) :
            ev_loop{std::move(loop_ptr)}, loop_thread_id{thread_id}
    {
        assert(ev_loop);
        log::trace(log_cat, "Beginning event loop creation with pre-existing ev loop thread");

        setup_job_waker();

        running.store(true);
    }

    static std::vector<std::string_view> get_ev_methods()
    {
        std::vector<std::string_view> ev_methods_avail;
        for (const char** methods = event_get_supported_methods(); methods && *methods; methods++)
            ev_methods_avail.emplace_back(*methods);
        return ev_methods_avail;
    }

    Loop::Loop()
    {
        log::trace(log_cat, "Beginning loop context creation with new ev loop thread");

#ifdef _WIN32
        {
            WSADATA ignored;
            if (int err = WSAStartup(MAKEWORD(2, 2), &ignored); err != 0)
            {
                log::critical(log_cat, "WSAStartup failed to initialize the windows socket layer ({:x})", err);
                throw std::runtime_error{"Unable to initialize windows socket layer"};
            }
        }
#endif

        if (static bool once = false; !once)
        {
            once = true;
            setup_libevent_logging();

            // Older versions of libevent do not like having this called multiple times
#ifdef _WIN32
            evthread_use_windows_threads();
#else
            evthread_use_pthreads();
#endif
        }

        static std::vector<std::string_view> ev_methods_avail = get_ev_methods();
        log::debug(
                log_cat,
                "Starting libevent {}; available backends: {}",
                event_get_version(),
                "{}"_format(fmt::join(ev_methods_avail, ", ")));

        std::unique_ptr<event_config, decltype(&event_config_free)> ev_conf{event_config_new(), event_config_free};
        event_config_set_flag(ev_conf.get(), EVENT_BASE_FLAG_PRECISE_TIMER);
        event_config_set_flag(ev_conf.get(), EVENT_BASE_FLAG_EPOLL_USE_CHANGELIST);

        ev_loop = std::shared_ptr<event_base>{event_base_new_with_config(ev_conf.get()), event_base_free};

        log::info(log_cat, "Started libevent loop with backend {}", event_base_get_method(ev_loop.get()));

        setup_job_waker();

        std::promise<void> p;

        loop_thread.emplace([this, &p]() mutable {
            log::debug(log_cat, "Starting event loop run");
            p.set_value();
            event_base_loop(ev_loop.get(), EVLOOP_NO_EXIT_ON_EMPTY);
            log::debug(log_cat, "Event loop run returned, thread finished");
        });

        loop_thread_id = loop_thread->get_id();
        p.get_future().get();

        running.store(true);
        log::info(log_cat, "loop is started");
    }

    Loop::~Loop()
    {
        log::info(log_cat, "Shutting down loop...");

        if (loop_thread)
            event_base_loopbreak(ev_loop.get());

        if (loop_thread and loop_thread->joinable())
            loop_thread->join();

        log::info(log_cat, "Loop shutdown complete");

#ifdef _WIN32
        WSACleanup();
#endif
    }

    void Loop::shutdown(bool immediate)
    {
        log::info(log_cat, "Shutting down loop...");

        if (loop_thread)
            immediate ? event_base_loopbreak(ev_loop.get()) : event_base_loopexit(ev_loop.get(), nullptr);

        if (loop_thread and loop_thread->joinable())
            loop_thread->join();

        log::debug(log_cat, "Stopping all tickers...");

        for (auto t : _tickers)
        {
            if (auto tick = t.lock())
            {
                tick->f = nullptr;
                tick->stop();
            }
        }

        log::info(log_cat, "Loop shutdown complete");
    }

    void Loop::setup_job_waker()
    {
        job_waker.reset(event_new(
                ev_loop.get(),
                -1,
                0,
                [](evutil_socket_t, short, void* self) {
                    log::trace(log_cat, "processing job queue");
                    static_cast<Loop*>(self)->process_job_queue();
                },
                this));
        assert(job_waker);
    }

    void Loop::process_job_queue()
    {
        log::trace(log_cat, "Event loop processing job queue");
        assert(in_event_loop());

        decltype(job_queue) swapped_queue;

        {
            std::lock_guard<std::mutex> lock{job_queue_mutex};
            job_queue.swap(swapped_queue);
        }

        while (not swapped_queue.empty())
        {
            auto job = swapped_queue.front();
            swapped_queue.pop();
            job();
        }
    }

}  //  namespace oxen::quic
