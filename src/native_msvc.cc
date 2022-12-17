/*
 * Copyright (C) 2021-2022 Jianye Chen
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

#include <psp2cldr/implementation/native_msvc.hpp>

#include <cassert>
#include <intrin.h>
#include <excpt.h>

#include <psp2cldr/context.hpp>
#include <psp2cldr/implementation/logger.hpp>

#include <psp2cldr/utility/semaphore.hpp>

uint64_t NativeMemoryAccessProxy::copy_in(uint64_t dest, const void *src, size_t num) const
{
    void *real_dest = (void *)m_translator.translate(dest);
    memmove(real_dest, src, num);
    return dest;
}

void *NativeMemoryAccessProxy::copy_out(void *dest, uint64_t src, size_t num) const
{
    void *real_src = (void *)m_translator.translate(src);
    memmove(dest, real_src, num);
    return dest;
}

uint32_t RegisterAccessProxy_NativeMSVC::w(uint32_t value)
{
    // https://lists.gnu.org/archive/html/qemu-devel/2021-04/msg02211.html
    if (name() == Register::PC)
    {
        if (TESTBIT(value, 0))
        {
            clearbit(&value, 0);
            setbit(&m_engine->m_target_ctx.Cpsr, 5);
        }
        else
        {
            clearbit(&m_engine->m_target_ctx.Cpsr, 5);
        }
    }

    *(unsigned long*)((char*)(&(m_engine->m_target_ctx)) + reg_mapping.at(name())) =
        value;
    return value;
}

uint32_t RegisterAccessProxy_NativeMSVC::r() const
{
    const uint32_t value = *(unsigned long*)((char*)(&(m_engine->m_target_ctx)) + reg_mapping.at(name()));
    if (name() == Register::PC)
    {
        return CLEARBIT(value, 0);
    }
    return value;
}

thread_local ExecutionThread_NativeMSVC* tls_thread = nullptr;
thread_local ExecutionThread_NativeMSVC* tls_thread_init = nullptr;
thread_local ExecutionThread_NativeMSVC* tls_thread_return = nullptr;

static inline void _execute_recover_until_point(uintptr_t until, uint32_t backup, MemoryAccessProxy& proxy)
{
    if (TESTBIT(until, 0)) // thumb
    {
        proxy.copy_in(CLEARBIT(until, 0), &backup, 2);
    }
    else
    {
        proxy.copy_in(until, &backup, 4);
    }
}

int thread_handle_signal()
{
    ExecutionThread_NativeMSVC* thread = tls_thread;
    ExecutionThread::THREAD_EXECUTION_RESULT result = ExecutionThread::THREAD_EXECUTION_RESULT::OK;
    auto pc = (*thread)[RegisterAccessProxy::Register::PC]->r();
    pc += thread->is_thumb() ? 1 : 0;

    if (thread->m_stop_called)
    {
        result = ExecutionThread::THREAD_EXECUTION_RESULT::STOP_CALLED;
        goto _done;
    }

    if (pc != thread->m_target_until_point)
    {
        LOG(TRACE, "execute({}): handling interrupt si_signo={:#x} pc={:#010x} si_addr={:#010x}",
            thread->tid(), thread->m_exception_record.ExceptionCode, pc, (uint32_t)thread->m_exception_record.ExceptionAddress);
        if (thread->m_exception_record.ExceptionCode == EXCEPTION_ACCESS_VIOLATION || thread->m_exception_record.ExceptionCode == EXCEPTION_ILLEGAL_INSTRUCTION)
        {
            switch (thread->m_exception_record.ExceptionCode)
            {
            case EXCEPTION_ACCESS_VIOLATION:
                thread->m_intr_callback(thread->m_coord, *thread, POSIX_SIGSEGV);
                break;
            case EXCEPTION_ILLEGAL_INSTRUCTION:
                thread->m_intr_callback(thread->m_coord, *thread, POSIX_SIGILL);
                break;
            }

            // make sure we don't accidentally change thread_obj_key in a nested scenario
            assert(thread == tls_thread);

            if (thread->m_stop_called)
            {
                LOG(TRACE, "execute({}): stop() called, done", thread->tid());
                result = ExecutionThread::THREAD_EXECUTION_RESULT::STOP_CALLED;
            }
            else
            {
                LOG(TRACE, "execute({}): interrupt handling complete, resuming execution at {:#010x}", thread->tid(),
                    (*thread)[RegisterAccessProxy::Register::PC]->r());

                thread->m_handling_interrupt = false;

                return EXCEPTION_CONTINUE_EXECUTION;
            }
        }
        else
        {
            LOG(TRACE, "execute({}): unexpected interrupt, stopping", thread->tid());
            thread->stop(1);
            result = ExecutionThread::THREAD_EXECUTION_RESULT::STOP_ERRORED;
        }
    }
    else
    {
        LOG(TRACE, "execute({}): STOP_UNTIL_POINT_HIT, done", thread->tid());

        result = ExecutionThread::THREAD_EXECUTION_RESULT::STOP_UNTIL_POINT_HIT;
    }

_done:
    // we need to be able to call pthread_kill to stop()
    // but we can't use m_thread_lock because if the thread is currently being joined, we won't be able to get that lock
    // so we need another semaphore to signal whether it is safe to exit this thread
    thread->m_exitwait.acquire();

    tls_thread = nullptr;

    _execute_recover_until_point(thread->m_target_until_point, thread->m_until_point_instr_backup,
        thread->m_coord.proxy());

    thread->m_result = result;
    thread->m_state = ExecutionThread::THREAD_EXECUTION_STATE::RESTARTABLE;
    thread->m_handling_interrupt = false;

    thread->m_stop_called = false;

    ExitThread(0);
    return EXCEPTION_CONTINUE_EXECUTION;
}

LONG NTAPI _GlobalExceptionHandler(_EXCEPTION_POINTERS* ep)
{
    unsigned int code = ep->ExceptionRecord->ExceptionCode;
    if (code == EXCEPTION_ILLEGAL_INSTRUCTION)
    {
        if (tls_thread_init != nullptr)
        {
            clearbit(&ep->ContextRecord->Pc, 0);
            tls_thread_init->m_target_ctx = *ep->ContextRecord;

            // we forced it with 0xffffffff, so always advance by 4
            ep->ContextRecord->Pc += 4;

            tls_thread_init = nullptr;
            return EXCEPTION_CONTINUE_EXECUTION;
        }
        else if (tls_thread_return != nullptr)
        {
            *ep->ContextRecord = tls_thread_return->m_target_ctx;

            // Jazelle, see DDI0406C A.2.5.1
            if (TESTBIT(ep->ContextRecord->Cpsr, 24))
            {
                clearbit(&ep->ContextRecord->Cpsr, 24);
            }
            assert(!TESTBIT(ep->ContextRecord->Pc, 0));

            tls_thread_return = nullptr;

            // this thread should never come back here again

            return EXCEPTION_CONTINUE_EXECUTION;
        }
    }

    if (code == EXCEPTION_SINGLE_STEP || code == EXCEPTION_BREAKPOINT || code == EXCEPTION_ACCESS_VIOLATION)
    {
        return EXCEPTION_CONTINUE_SEARCH;
    }

    if (tls_thread != nullptr)
    {
        if (tls_thread->m_handling_interrupt)
        {
            if (tls_thread->m_stop_called)
            {
                return EXCEPTION_CONTINUE_EXECUTION;
            }

            // debugger will likely catch this if attached
            return EXCEPTION_CONTINUE_SEARCH;
        }
        else
        {
            clearbit(&ep->ContextRecord->Pc, 0);

            tls_thread->m_handling_interrupt = true;
            tls_thread->m_target_ctx = *ep->ContextRecord;
            tls_thread->m_exception_record = *ep->ExceptionRecord;

            int result = thread_handle_signal();
            if (result == EXCEPTION_CONTINUE_EXECUTION)
            {
                *ep->ContextRecord = tls_thread->m_target_ctx;
            }
            return result;
        }
    }

    return EXCEPTION_CONTINUE_SEARCH;
}

void _trigger_sigill()
{
    std::atomic_signal_fence(std::memory_order_seq_cst);

    // this is ugly... but we can't do a UDF easily in msvc...
    __emit(0xffff);
    __emit(0xffff);

    std::atomic_signal_fence(std::memory_order_seq_cst);
}

ExecutionThread_NativeMSVC::ExecutionThread_NativeMSVC(ExecutionCoordinator& coord) : m_coord(coord)
{
    // cannot use thread_obj_key here, we could be nested inside provider function
    // which will overwrite the callers provider key
    tls_thread_init = this;
    
    _trigger_sigill();

    assert(tls_thread_init == nullptr);
}

ExecutionThread_NativeMSVC::~ExecutionThread_NativeMSVC()
{
}

uintptr_t NativeMSVCEngineARM::mmap(uintptr_t preferred, size_t length)
{
    std::lock_guard g{ m_memory_lock };
    auto ptr = m_allocator.alloc(0x1000, length);
    if (ptr)
    {
        m_translator.add(ptr, length, ptr);
    }
    return ptr;
}

int NativeMSVCEngineARM::munmap(uintptr_t addr, size_t length)
{
    std::lock_guard g{ m_memory_lock };
    auto ptr = m_translator.translate(addr);
    m_translator.erase(addr, length);
    m_allocator.free(ptr);
    return 0;
}

[[nodiscard]] std::shared_ptr<ExecutionThread> NativeMSVCEngineARM::thread_create()
{
    auto thread = std::make_shared<ExecutionThread_NativeMSVC>(*this);
    thread->register_interrupt_callback(m_intr_callback);
    auto casted = std::dynamic_pointer_cast<ExecutionThread>(thread);

    std::lock_guard guard{ m_threads_lock };
    m_threads.insert(casted);

    return casted;
}

int NativeMSVCEngineARM::thread_destroy(std::weak_ptr<ExecutionThread> thread)
{
    if (auto p = thread.lock())
    {
        std::lock_guard guard{ m_threads_lock };
        if (m_threads.count(p) != 0)
        {
            p->stop();
            p->join();
            m_threads.erase(p);

            return 0;
        }

        return 1;
    }
    return 2;
}

void NativeMSVCEngineARM::thread_joinall()
{
    do
    {
        size_t left;
        std::shared_ptr<ExecutionThread> p;

        {
            std::lock_guard guard{ m_threads_lock };

            left = m_threads.size();
            if (left)
                p = *m_threads.begin();
        }

        if (left)
            p->join();
        else
            break;
    } while (1);
}

void NativeMSVCEngineARM::thread_stopall(int retval)
{
    std::lock_guard guard{ m_threads_lock };
    for (auto& thread : m_threads)
        thread->stop();
}

struct thread_bootstrap_args
{
    ExecutionThread_NativeMSVC* thread;

    semaphore barrier;

    ExecutionThread::THREAD_EXECUTION_RESULT start_result;
};

void thread_bootstrap(thread_bootstrap_args* args)
{
    tls_thread = args->thread;
    args->start_result = ExecutionThread::THREAD_EXECUTION_RESULT::OK;
    args->barrier.release();
    args = nullptr;

    tls_thread_return = tls_thread;

    // HAX: NT checks stack validity on EH return, but we allocate our own stack
    // FAIL_FAST_INVALID_SET_OF_CONTEXT_c0000409_ntdll.dll!RtlGuardRestoreContext
    NT_TIB* teb = (NT_TIB*)NtCurrentTeb();
    LOG(TRACE, "NT TEB stack_base={:#010x} stack_limit={:#010x}", (uint32_t)teb->StackBase, (uint32_t)teb->StackLimit);
    teb->StackBase = (void*)0xff000000;
    teb->StackLimit = (void*)0x1000;

    LOG(TRACE, "bootstrap complete");

    _trigger_sigill();
}

ExecutionThread::THREAD_EXECUTION_RESULT ExecutionThread_NativeMSVC::start(uint32_t from, uint32_t until)
{
    switch (m_state)
    {
    case THREAD_EXECUTION_STATE::UNSTARTED:
    case THREAD_EXECUTION_STATE::RESTARTABLE:
        break;
    default:
        return ExecutionThread::THREAD_EXECUTION_RESULT::START_FAILED;
    }

    assert(m_thread == nullptr);

    (*this)[RegisterAccessProxy::Register::PC]->w(from);
    assert(TESTBIT(from, 0) ? is_thumb() : 1);
    assert((*this)[RegisterAccessProxy::Register::PC]->r() == CLEARBIT(from, 0));

    static const uint32_t INSTR_UDF0_ARM = 0xe7f000f0;
    static const uint16_t INSTR_UDF0_THM = 0xde00;

    if (TESTBIT(until, 0)) // thumb
    {
        m_until_point_instr_backup = m_coord.proxy().r<uint16_t>(CLEARBIT(until, 0));
        m_coord.proxy().w<uint16_t>(CLEARBIT(until, 0), INSTR_UDF0_THM);
    }
    else
    {
        m_until_point_instr_backup = m_coord.proxy().r<uint32_t>(CLEARBIT(until, 0));
        m_coord.proxy().w<uint32_t>(CLEARBIT(until, 0), INSTR_UDF0_ARM);
    }

    m_target_until_point = until;


    thread_bootstrap_args args;
    args.thread = this;
    args.start_result = THREAD_EXECUTION_RESULT::START_FAILED;
    {
        std::lock_guard guard{ m_thread_lock };

        m_state = THREAD_EXECUTION_STATE::RUNNING;
        m_result = THREAD_EXECUTION_RESULT::OK;

        m_thread = std::make_unique<std::thread>(thread_bootstrap, &args);

        m_exitwait.release();
    }

    args.barrier.acquire();
    return args.start_result;
    
}

ExecutionThread::THREAD_EXECUTION_RESULT ExecutionThread_NativeMSVC::join(uint32_t* retval)
{
    if (m_state != THREAD_EXECUTION_STATE::UNSTARTED)
    {
        // https://udrepper.livejournal.com/16844.html
        {
            std::lock_guard guard{ m_thread_lock };
            if (m_thread)
            {
                m_thread->join();
                m_thread = nullptr;
            }
        }

        if (m_result == THREAD_EXECUTION_RESULT::STOP_UNTIL_POINT_HIT && retval != nullptr)
            *retval = (*this)[RegisterAccessProxy::Register::R0]->r();

        return m_result;
    }
    return THREAD_EXECUTION_RESULT::JOIN_FAILED;
}

void ExecutionThread_NativeMSVC::stop(uint32_t retval)
{
    m_stop_called = true;

    // TODO: how do we signal an exception inside SEH? pthread_kill w/ signal?
    //{
    //    if (m_exitwait.try_acquire())
    //    {
    //        // the target thread won't be able to exit
    //        if (pthread_equal(pthread_self(), m_thread) == 0) // if not equal
    //        {
    //            pthread_kill(m_thread, SIGILL);
    //        }
    //        m_exitwait.release();
    //    }
    //}
}

NativeMSVCEngineARM::NativeMSVCEngineARM() : ExecutionCoordinator()
{
    m_ehhandle = AddVectoredExceptionHandler(1, _GlobalExceptionHandler);
    assert(m_ehhandle);
}

NativeMSVCEngineARM::~NativeMSVCEngineARM()
{
    RemoveVectoredExceptionHandler(m_ehhandle);
    m_ehhandle = nullptr;
}

#include <psp2cldr/context.hpp>

void ExecutionThread_NativeMSVC::panic(int code, LoadContext* load)
{
}

void NativeMSVCEngineARM::panic(int code, LoadContext* load)
{
    PANIC_LOG("Backend: NativeEngineARM");
    thread_stopall(code);

    std::lock_guard guard{ m_threads_lock };
    for (auto& p_thread : m_threads)
    {
        PANIC_LOG("Thread: tid={:#x}", p_thread->tid());
#define reg_info_dump(reg)                                                                                             \
    {                                                                                                                  \
        auto _reg_val = (*p_thread)[RegisterAccessProxy::Register::reg]->r();                                          \
        if (load)                                                                                                      \
        {                                                                                                              \
            auto _pair = load->try_resolve_location(_reg_val);                                                         \
            if (!_pair.first.empty())                                                                                  \
                PANIC_LOG("\t{}={:#010x}\t<{} + {:#010x}>", #reg, _reg_val, _pair.first, _pair.second);                \
            else                                                                                                       \
                PANIC_LOG("\t{}={:#010x}\t<\?\?>", #reg, _reg_val);                                                    \
        }                                                                                                              \
        else                                                                                                           \
            PANIC_LOG("\t{}={:#010x}", #reg, _reg_val);                                                                \
    }

        reg_info_dump(R0);
        reg_info_dump(R1);
        reg_info_dump(R2);
        reg_info_dump(R3);
        reg_info_dump(R4);
        reg_info_dump(R5);
        reg_info_dump(R6);
        reg_info_dump(R7);
        reg_info_dump(R8);
        reg_info_dump(R9);
        reg_info_dump(R10);
        reg_info_dump(FP);
        reg_info_dump(IP);
        reg_info_dump(SP);
        reg_info_dump(LR);
        reg_info_dump(PC);
        PANIC_LOG("\tCPSR={:#032b}", (*p_thread)[RegisterAccessProxy::Register::CPSR]->r());

        try
        {
            PANIC_LOG("\tinstr@PC={:#010x}", proxy().r<uint32_t>((*p_thread)[RegisterAccessProxy::Register::PC]->r()));
        }
        catch (...)
        {
        }
    }
}
