#ifndef PSP2CLDR_EXECCOORD_H
#define PSP2CLDR_EXECCOORD_H

#include <atomic>
#include <cstdint>
#include <exception>
#include <functional>
#include <memory>

#include <psp2cldr/access_proxy.hpp>
#include <psp2cldr/panic.hpp>

class InterruptContext;

class ExecutionCoordinator;
class ExecutionThread : public PanicDumpable
{
private:
    static inline std::atomic<uint32_t> _id_ctr = 1;
    mutable uint32_t m_tid = 0;

public:
    uint32_t tid() const
    {
        if (m_tid == 0)
            return m_tid = _id_ctr ++;
        return m_tid;
    }

public:
    ExecutionThread() {}
    virtual ~ExecutionThread() {}

public:
    enum class THREAD_EXECUTION_STATE
    {
        UNSTARTED,
        RUNNING,
        RESTARTABLE,
        EXITED // died, will never leave this state
    };
    // thread is not accessible when it's running
    // we can attempt to wait for the thread to become inspect-able

    enum class THREAD_EXECUTION_RESULT
    {
        OK,
        START_FAILED,
        JOIN_FAILED,
        STOP_UNTIL_POINT_HIT,
        STOP_CALLED,
        STOP_ERRORED
    };

    virtual const std::atomic<THREAD_EXECUTION_STATE> &state() const = 0;
    virtual THREAD_EXECUTION_RESULT start(uint32_t from, uint32_t until) = 0;
    virtual THREAD_EXECUTION_RESULT join(uint32_t *retval = nullptr) = 0; // retval is set iff result is STOP_UNTIL_POINT_HIT
    virtual void stop(uint32_t retval = 0) = 0;

    virtual void register_interrupt_callback(std::function<void(ExecutionCoordinator &, ExecutionThread &, uint32_t)> callback) = 0;

public:
    // register access
    virtual std::shared_ptr<RegisterAccessProxy> operator[](RegisterAccessProxy::Register name) = 0;
    virtual std::shared_ptr<const RegisterAccessProxy> operator[](RegisterAccessProxy::Register name) const = 0;
};

class ExecutionCoordinator : public PanicDumpable
{
public:
    ExecutionCoordinator() {}
    virtual ~ExecutionCoordinator() {}

public:
    virtual MemoryAccessProxy &proxy() const = 0;
    virtual uintptr_t mmap(uintptr_t preferred, size_t length) = 0; // always RWX
    virtual int munmap(uintptr_t addr, size_t length) = 0;

    /**
     * Threading Support
     * on platforms that does not natively support target threading, only a single thread of execution on the target will be active at any given time.
     */
    [[nodiscard]] virtual std::shared_ptr<ExecutionThread> thread_create() = 0;
    virtual int thread_destory(std::weak_ptr<ExecutionThread> thread) = 0;
    virtual void thread_joinall() = 0;
    virtual void thread_stopall(int retval = 0) = 0;

    virtual void panic(int code = 0, PanicDumpable *dumpable = nullptr)
    {
        if (dumpable == nullptr)
            dumpable = this;
        psp2cldr_panic(code, dumpable);
        thread_stopall(code);
    }

    // default interrupt callback for all newly created threads
    virtual void register_interrupt_callback(std::function<void(ExecutionCoordinator &, ExecutionThread &, uint32_t)> callback) = 0;
};

// when running natively, exec state control is ~equivalent to a gdb client

#endif
