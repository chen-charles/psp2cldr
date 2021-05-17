#ifndef _SEMA_H
#define _SEMA_H

#include <chrono>
#include <condition_variable>
#include <mutex>
#include <thread>

class semaphore
{
public:
    semaphore(uintptr_t initial = 0) : m_ct(initial) {}
    virtual ~semaphore() {}

    void acquire()
    {
        std::unique_lock lk{m_lock};
        m_cv.wait(lk, [&]()
                  { return m_ct; });
        m_ct--;
    }

    template <class Rep, class Period>
    bool acquire_for(std::chrono::duration<Rep, Period> dur)
    {
        std::unique_lock lk{m_lock};
        if (m_cv.wait_for(lk, dur, [&]()
                          { return m_ct; }))
        {
            m_ct--;
            return true;
        }
        return false;
    }

    bool try_acquire()
    {
        std::unique_lock lk{m_lock};
        if (m_ct)
        {
            m_ct--;
            return true;
        }
        return false;
    }

    void release()
    {
        std::unique_lock lk{m_lock};
        m_ct++;
        m_cv.notify_one();
    }

protected:
    std::mutex m_lock;
    std::condition_variable m_cv;
    uintptr_t m_ct = 0;
};

template <class T>
class semaphore_guard
{
public:
    semaphore_guard(T &sema) : m_sema(sema) { m_sema.acquire(); }
    semaphore_guard(const T &) = delete;
    virtual ~semaphore_guard() { m_sema.release(); }

private:
    T &m_sema;
};

#endif
