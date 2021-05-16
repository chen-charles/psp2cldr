#include <cassert>
#include <sys/mman.h>
#include <unistd.h>

#include <psp2cldr/logger.hpp>
#include <psp2cldr/native.hpp>

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

uint32_t RegisterAccessProxy_Native::w(uint32_t value)
{
    *((unsigned long int *)(&(m_engine->m_target_ctx.uc_mcontext.arm_r0)) + reg_mapping.at(name())) = value; // implementation specific, assuming glibc
    return value;
}

uint32_t RegisterAccessProxy_Native::r() const
{
    return *((unsigned long int *)(&(m_engine->m_target_ctx.uc_mcontext.arm_r0)) + reg_mapping.at(name()));
}

[[noreturn]] static void do_return(ucontext_t *ucp) /* HAX, but at least it's better than siglongjmp */
{
    if (setcontext(ucp) == -1)
        raise(SIGTRAP); /* unfortunately, we are dead ... */
    __builtin_unreachable();
}

void _sig_handler(int sig, siginfo_t *info, void *ucontext)
{
    static NativeEngineARM *coord = NULL;
    if (info->si_code == SI_QUEUE && info->si_value.sival_ptr != NULL)
    {
        coord = reinterpret_cast<NativeEngineARM *>(info->si_value.sival_ptr);
        return;
    }

    if (!coord)
    {
        // ??
        raise(SIGTRAP);
    }

    std::shared_ptr<ExecutionThread_Native> exec_thread;
    auto thread_id = pthread_self();
    {
        while (coord->m_threads_lock.test_and_set())
            ;

        for (auto &thread : coord->m_threads)
        {
            auto casted = std::dynamic_pointer_cast<ExecutionThread_Native>(thread);
            if (pthread_equal(casted->pthread_id(), thread_id))
            {
                exec_thread = casted;
                break;
            }
        }

        coord->m_threads_lock.clear();
    }

    if (!exec_thread)
    {
        if (coord->m_old_action.sa_flags & SA_SIGINFO)
            (coord->m_old_action.sa_sigaction)(sig, info, ucontext);
        else
            (coord->m_old_action.sa_handler)(sig);
    }

    auto ctx = reinterpret_cast<ucontext_t *>(ucontext);

    if (!exec_thread->m_started)
        return;

    exec_thread->m_target_ctx = *ctx;
    exec_thread->m_target_siginfo = *info;

    if (exec_thread->m_target_ctx.uc_mcontext.arm_pc != exec_thread->m_target_until_point)
        exec_thread->m_handling_interrupt = true;

    /* HAX, but at least it's better than siglongjmp */
    uint32_t do_return_addr = (uint32_t) & (do_return);
    ctx->uc_mcontext.arm_r0 = (uint32_t) & (exec_thread->m_return_ctx);
    ctx->uc_mcontext.arm_pc = do_return_addr & (~1);
    if (do_return_addr % 2) // thumb
        ctx->uc_mcontext.arm_cpsr |= 1 << 5;
    else
        ctx->uc_mcontext.arm_cpsr &= ~(1 << 5);
    // we need a minimal C running environment, which involves a stack
    ctx->uc_mcontext.arm_sp = (uint32_t)(&exec_thread->do_return_stack) + DO_RETURN_STACK_SZ;

    // execution resumes in execute, or we are dead
}

static inline void _execute_recover_until_point(uintptr_t until, uint32_t backup, MemoryAccessProxy &proxy)
{
    if (until & 1) // thumb
    {
        proxy.copy_in(until & (~1), &backup, 2);
    }
    else
    {
        proxy.copy_in(until, &backup, 4);
    }
}

ExecutionThread_Native::ExecutionThread_Native(ExecutionCoordinator &coord) : m_coord(coord)
{
    if (getcontext(&m_target_ctx) != 0)
        throw std::runtime_error("getcontext failed");
}

void *thread_bootstrap(ExecutionThread_Native *thread)
{
    ExecutionThread::THREAD_EXECUTION_RESULT result = ExecutionThread::THREAD_EXECUTION_RESULT::START_FAILED;

    /* HAX, but at least it's better than sigsetjmp */
    if (getcontext(&thread->m_return_ctx) == 0)
    {
        if (!thread->m_started)
        {
            LOG(TRACE, "execute({}): ready to start", thread->tid());
            thread->m_started = true;

            setcontext(&thread->m_target_ctx); // no return, or it failed
            LOG(CRITICAL, "setcontext failed with error: {}", strerror(errno));
            throw std::runtime_error("unrecoverable failure");
        }
        else
            goto _execute_signal_callback;
    }
    else
    {
        LOG(CRITICAL, "getcontext failed with error: {}", strerror(errno));
        throw std::runtime_error("unrecoverable failure");
    }

_execute_signal_callback:
    if (thread->m_stop_called)
    {
        result = ExecutionThread::THREAD_EXECUTION_RESULT::STOP_CALLED;
        goto _done;
    }

    if (thread->m_handling_interrupt)
    {
        LOG(TRACE, "execute({}): handling interrupt si_signo={:#x}", thread->tid(), thread->m_target_siginfo.si_signo);
        if (thread->m_target_siginfo.si_signo == SIGILL)
        {
            thread->m_intr_callback(thread->m_coord, *thread, thread->m_target_siginfo.si_signo);

            if (thread->m_stop_called)
            {
                LOG(TRACE, "execute({}): stop() called, done", thread->tid());
                result = ExecutionThread::THREAD_EXECUTION_RESULT::STOP_CALLED;
            }
            else
            {
                LOG(TRACE, "execute({}): interrupt handling complete, resuming execution", thread->tid());

                // continue target execution
                thread->m_handling_interrupt = false;

                setcontext(&thread->m_target_ctx); // no return, or it failed

                result = ExecutionThread::THREAD_EXECUTION_RESULT::STOP_ERRORED;
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

        thread->m_started = false;
        result = ExecutionThread::THREAD_EXECUTION_RESULT::STOP_UNTIL_POINT_HIT;
    }

_done:
    _execute_recover_until_point(thread->m_target_until_point, thread->m_until_point_instr_backup, thread->m_coord.proxy());
    thread->m_result = result;

    thread->m_started = false;
    thread->m_handling_interrupt = false;
    thread->m_state = ExecutionThread::THREAD_EXECUTION_STATE::RESTARTABLE;
    thread->m_stoppable = false;
    return NULL;
}

ExecutionThread::THREAD_EXECUTION_RESULT ExecutionThread_Native::start(uint32_t from, uint32_t until)
{
    switch (m_state)
    {
    case THREAD_EXECUTION_STATE::UNSTARTED:
    case THREAD_EXECUTION_STATE::RESTARTABLE:
        break;
    default:
        return ExecutionThread::THREAD_EXECUTION_RESULT::START_FAILED;
    }

    join(nullptr);

    (*this)[RegisterAccessProxy::Register::PC]->w(from);

    static const uint32_t INSTR_UDF0_ARM = 0xe7f000f0;
    static const uint16_t INSTR_UDF0_THM = 0xde00;

    if (until & 1) // thumb
    {
        m_until_point_instr_backup = m_coord.proxy().r<uint16_t>(until & (~1));
        m_coord.proxy().w<uint16_t>(until & (~1), INSTR_UDF0_THM);
    }
    else
    {
        m_until_point_instr_backup = m_coord.proxy().r<uint32_t>(until & (~1));
        m_coord.proxy().w<uint32_t>(until & (~1), INSTR_UDF0_ARM);
    }

    m_target_until_point = until;
    if (pthread_create(&m_thread, NULL, (void *(*)(void *))thread_bootstrap, this) != 0)
    {
        _execute_recover_until_point(until, m_until_point_instr_backup, m_coord.proxy());
        throw std::runtime_error("pthread_create failed");
    }

    m_state = THREAD_EXECUTION_STATE::RUNNING;
    m_stoppable = true;
    return THREAD_EXECUTION_RESULT::OK;
}

ExecutionThread::THREAD_EXECUTION_RESULT ExecutionThread_Native::join(uint32_t *retval)
{
    if (m_state != THREAD_EXECUTION_STATE::UNSTARTED)
    {
        void *thread_retval;
        auto err = pthread_join(m_thread, &thread_retval);
        if (err == 0 || err == EINVAL)
        {
            if (m_result == THREAD_EXECUTION_RESULT::STOP_UNTIL_POINT_HIT && retval != nullptr)
                *retval = (*this)[RegisterAccessProxy::Register::R0]->r();

            return m_result;
        }
    }
    return THREAD_EXECUTION_RESULT::JOIN_FAILED;
}

void ExecutionThread_Native::stop(uint32_t retval)
{
    m_stop_called = true;
    if (m_stoppable && !pthread_equal(m_thread, pthread_self()))
    {
        union sigval sig_v;
        sig_v.sival_ptr = NULL;
        pthread_sigqueue(m_thread, SIGILL, sig_v);
    }
}

uintptr_t NativeEngineARM::mmap(uintptr_t preferred, size_t length)
{
    std::lock_guard g{m_memory_lock};
    auto ptr = m_allocator.alloc(0x1000, length);
    m_translator.add(ptr, length, ptr);
    return ptr;
}

int NativeEngineARM::munmap(uintptr_t addr, size_t length)
{
    std::lock_guard g{m_memory_lock};
    auto ptr = m_translator.translate(addr);
    m_translator.erase(addr, length);
    m_allocator.free(ptr);
    return 0;
}

[[nodiscard]] std::shared_ptr<ExecutionThread> NativeEngineARM::thread_create()
{
    auto thread = std::make_shared<ExecutionThread_Native>(*this);
    thread->register_interrupt_callback(m_intr_callback);
    auto casted = std::dynamic_pointer_cast<ExecutionThread>(thread);

    while (m_threads_lock.test_and_set())
        ;

    m_threads.insert(casted);

    m_threads_lock.clear();

    return casted;
}

int NativeEngineARM::thread_destroy(std::weak_ptr<ExecutionThread> thread)
{
    if (auto p = thread.lock())
    {
        while (m_threads_lock.test_and_set())
            ;
        if (m_threads.count(p) != 0)
        {
            p->stop();
            p->join();
            m_threads.erase(p);

            m_threads_lock.clear();
            return 0;
        }
        m_threads_lock.clear();

        return 1;
    }
    return 2;
}

void NativeEngineARM::thread_joinall()
{
    do
    {
        size_t left;
        std::shared_ptr<ExecutionThread> p;

        {
            while (m_threads_lock.test_and_set())
                ;

            left = m_threads.size();
            if (left)
                p = *m_threads.begin();
            m_threads_lock.clear();
        }

        if (left)
            p->join();
        else
            break;
    } while (1);
}

void NativeEngineARM::thread_stopall(int retval)
{
    while (m_threads_lock.test_and_set())
        ;
    for (auto &thread : m_threads)
        thread->stop();
    m_threads_lock.clear();
}

#include <psp2cldr/context.hpp>

void ExecutionThread_Native::panic(int code, LoadContext *load)
{
}

void NativeEngineARM::panic(int code, LoadContext *load)
{
    PANIC_LOG("Backend: NativeEngineARM");
    while (m_threads_lock.test_and_set())
        ;
    for (auto &p_thread : m_threads)
    {
        PANIC_LOG("Thread: tid={:#x}", p_thread->tid());
#define reg_info_dump(reg)                                                                              \
    {                                                                                                   \
        auto _reg_val = (*p_thread)[RegisterAccessProxy::Register::reg]->r();                           \
        if (load)                                                                                       \
        {                                                                                               \
            auto _pair = load->try_resolve_location(_reg_val);                                          \
            if (!_pair.first.empty())                                                                   \
                PANIC_LOG("\t{}={:#010x}\t<{} + {:#010x}>", #reg, _reg_val, _pair.first, _pair.second); \
            else                                                                                        \
                PANIC_LOG("\t{}={:#010x}\t<\?\?>", #reg, _reg_val);                                     \
        }                                                                                               \
        else                                                                                            \
            PANIC_LOG("\t{}={:#010x}", #reg, _reg_val);                                                 \
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
    m_threads_lock.clear();
}

NativeEngineARM::NativeEngineARM() : ExecutionCoordinator()
{
    stack_t ss;
    ss.ss_size = SIGSTKSZ;
    ss.ss_flags = 0;
    ss.ss_sp = (void *)m_sigstack;
    if (sigaltstack(&ss, &m_old_ss) == 0)
    {
        struct sigaction action;
        sigfillset(&action.sa_mask);
        action.sa_sigaction = _sig_handler;
        action.sa_flags = SA_SIGINFO | SA_ONSTACK;
        if (sigaction(SIGILL, &action, &m_old_action) == 0)
        {
            union sigval sig_v;
            sig_v.sival_ptr = this;
            if (sigqueue(getpid(), SIGILL, sig_v) == 0)
            {
                // setup complete
                return;
            }
            else
            {
                LOG(CRITICAL, "sigqueue failed with error: {}", strerror(errno));
            }
            sigaction(SIGILL, &m_old_action, NULL);
        }
        else
        {
            LOG(CRITICAL, "sigaction failed with error: {}", strerror(errno));
        }
        sigaltstack(&m_old_ss, NULL);
    }
    else
    {
        LOG(CRITICAL, "sigaltstack failed with error: {}", strerror(errno));
    }

    throw std::runtime_error("NativeEngineARM initialization failed");
}

NativeEngineARM::~NativeEngineARM()
{
    sigaction(SIGILL, &m_old_action, NULL);
    sigaltstack(&m_old_ss, NULL);
}
