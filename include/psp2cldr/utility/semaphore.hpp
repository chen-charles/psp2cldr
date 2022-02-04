/*
 * Copyright (C) 2021-2022 Jianye Chen
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

#ifndef PSP2CLDR_SEMA_H
#define PSP2CLDR_SEMA_H

#include <chrono>
#include <condition_variable>
#include <memory>
#include <mutex>
#include <thread>

#include <psp2cldr/utility/delegate.hpp>

class semaphore
{
  public:
    semaphore(uintptr_t initial = 0) : m_ct(initial)
    {
    }
    virtual ~semaphore()
    {
    }

    void acquire()
    {
        std::unique_lock lk{m_lock};
        m_cv.wait(lk, [&]() { return m_ct; });
        m_ct--;
    }

    class canceler
    {
        friend class scoped_canceler;
        mutable semaphore *sema;

      protected:
        std::atomic<bool> cancelled{false};

      public:
        class scoped_canceler
        {
            const canceler &canc;

          public:
            scoped_canceler(const canceler &in_canc, semaphore *in_sema) : canc(in_canc)
            {
                canc.sema = in_sema;
            }

            ~scoped_canceler()
            {
                canc.on_completed.broadcast();
                canc.sema = nullptr;
            }
        };

        void cancel()
        {
            cancelled = true;
            sema->m_cv.notify_all();
        }

        bool is_cancelled() const
        {
            return cancelled;
        }

        MulticastDelegate<std::function<void()>> on_completed;
    };

    template <class Rep, class Period>
    bool cancellable_acquire_for(std::chrono::duration<Rep, Period> dur, const canceler &canc = {})
    {
        std::unique_lock lk{m_lock};

        canceler::scoped_canceler scoped(canc, this);

        if (canc.is_cancelled())
        {
            return false;
        }

        if (m_cv.wait_for(lk, dur, [&]() {
                if (canc.is_cancelled())
                {
                    return true;
                }
                return m_ct != 0;
            }))
        {
            if (canc.is_cancelled())
            {
                return false;
            }

            m_ct--;
            return true;
        }
        return false;
    }

    template <class Rep, class Period, class LockGuardClass>
    bool cancellable_acquire_for(std::chrono::duration<Rep, Period> dur, LockGuardClass &guard,
                                 const canceler &canc = {})
    {
        std::unique_lock lk{m_lock};

        guard.unlock();

        canceler::scoped_canceler scoped(canc, this);

        if (canc.is_cancelled())
        {
            return false;
        }

        if (m_cv.wait_for(lk, dur, [&]() {
                if (canc.is_cancelled())
                {
                    return true;
                }
                return m_ct != 0;
            }))
        {
            if (canc.is_cancelled())
            {
                return false;
            }

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

template <class T> class semaphore_guard
{
  public:
    semaphore_guard(T &sema) : m_sema(sema)
    {
        m_sema.acquire();
    }
    semaphore_guard(const T &) = delete;
    virtual ~semaphore_guard()
    {
        m_sema.release();
    }

  private:
    T &m_sema;
};

#endif
