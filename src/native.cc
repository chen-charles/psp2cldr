#include <cassert>
#include <sys/mman.h>
#include <unistd.h>

#include <psp2cldr/logger.hpp>
#include <psp2cldr/native.hpp>

uint64_t NativeMemoryAccessProxy::copy_in(uint64_t dest, const void *src, size_t num) const
{
    return (uint64_t)memmove((void *)dest, src, num);
}

void *NativeMemoryAccessProxy::copy_out(void *dest, uint64_t src, size_t num) const
{
    return memmove(dest, (void *)src, num);
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

#define DO_RETURN_STACK_SZ 0x1000
static char do_return_stack[DO_RETURN_STACK_SZ] __attribute__((aligned(16)));
[[noreturn]] static void do_return(ucontext_t *ucp) /* HAX, but at least it's better than siglongjmp */
{
    if (setcontext(ucp) == -1)
        raise(SIGTRAP); /* unfortunately, we are dead ... */
    __builtin_unreachable();
}

void NativeEngineARM::_sig_handler(int sig, siginfo_t *info, void *ucontext)
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
    for (auto &thread : coord->m_threads)
    {
        auto casted = std::dynamic_pointer_cast<ExecutionThread_Native>(thread);
        if (pthread_equal(casted->id(), thread_id))
        {
            exec_thread = casted;
            break;
        }
    }
    if (!exec_thread)
    {
        if (coord->m_old_action.sa_flags & SA_SIGINFO)
            (coord->m_old_action.sa_sigaction)(sig, info, ucontext);
        else
            (coord->m_old_action.sa_handler)(sig);
    }

    auto ctx = reinterpret_cast<ucontext_t *>(ucontext);

    assert(exec_thread->m_started);
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
    ctx->uc_mcontext.arm_sp = (uint32_t)(&do_return_stack) + DO_RETURN_STACK_SZ;

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

void *ExecutionThread_Native::thread_bootstrap(ExecutionThread_Native *thread)
{
    ExecutionThread::THREAD_EXECUTION_RESULT result = THREAD_EXECUTION_RESULT::START_FAILED;

    /* HAX, but at least it's better than sigsetjmp */
    if (getcontext(&thread->m_return_ctx) == 0)
    {
        if (!thread->m_started)
        {
            LOG(TRACE, "execute: ready to start");
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
        result = THREAD_EXECUTION_RESULT::STOP_CALLED;
        goto _done;
    }

    if (thread->m_handling_interrupt)
    {
        LOG(TRACE, "execute: handling interrupt si_signo={:#x}", thread->m_target_siginfo.si_signo);
        if (thread->m_target_siginfo.si_signo == SIGILL)
        {
            thread->m_intr_callback(thread->m_coord, *thread, SIGILL);

            if (thread->m_stop_called)
            {
                LOG(TRACE, "execute: stop() called, done");
                result = THREAD_EXECUTION_RESULT::STOP_CALLED;
            }
            else
            {
                LOG(TRACE, "execute: interrupt handling complete, resuming execution");

                // continue target execution
                thread->m_handling_interrupt = false;

                setcontext(&thread->m_target_ctx); // no return, or it failed

                result = THREAD_EXECUTION_RESULT::STOP_ERRORED;
            }
        }
        else
        {
            LOG(TRACE, "execute: unexpected interrupt, stopping");
            thread->stop(1);
            result = THREAD_EXECUTION_RESULT::STOP_ERRORED;
        }
    }
    else
    {
        LOG(TRACE, "execute: STOP_UNTIL_POINT_HIT, done");

        thread->m_started = false;
        result = THREAD_EXECUTION_RESULT::STOP_UNTIL_POINT_HIT;
    }

_done:
    _execute_recover_until_point(thread->m_target_until_point, thread->m_until_point_instr_backup, thread->m_coord.proxy());
    thread->m_result = result;

    thread->m_started = false;
    thread->m_handling_interrupt = false;
    thread->m_stoppable = false;
    return NULL;
}

ExecutionThread::THREAD_EXECUTION_RESULT ExecutionThread_Native::start(uint32_t from, uint32_t until)
{
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

    m_stoppable = true;
    return THREAD_EXECUTION_RESULT::OK;
}

ExecutionThread::THREAD_EXECUTION_RESULT ExecutionThread_Native::join(uint32_t *retval)
{
    auto err = pthread_join(m_thread, (void **)&retval);
    if (err == 0 || err == EINVAL)
    {
        if (m_result == THREAD_EXECUTION_RESULT::STOP_UNTIL_POINT_HIT && retval != nullptr)
            *retval = (*this)[RegisterAccessProxy::Register::R0]->r();

        return m_result;
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
    auto ptr = m_allocator.alloc(0x1000, length);
    m_translator.add(ptr, length, ptr);
    return ptr;
}

int NativeEngineARM::munmap(uintptr_t addr, size_t length)
{
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
    m_threads.insert(casted);
    return casted;
}

int NativeEngineARM::thread_destory(std::weak_ptr<ExecutionThread> thread)
{
    if (auto p = thread.lock())
    {
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

void NativeEngineARM::thread_joinall()
{
    for (auto &thread : m_threads)
        thread->join();
}

void NativeEngineARM::thread_stopall(int retval)
{
    for (auto &thread : m_threads)
        thread->stop();
}

void NativeEngineARM::panic_dump_impl(std::shared_ptr<spdlog::logger> logger, int code)
{
    logger->info("Execution States");
    for (auto &p_thread : m_threads)
    {
        logger->info("Thread:");
#define reg_val(reg) (*p_thread)[RegisterAccessProxy::Register::reg]->r()
        logger->info("\tR0={:#010x}\t R1={:#010x}\t R2={:#010x}\t R3={:#010x}",
                     reg_val(R0),
                     reg_val(R1),
                     reg_val(R2),
                     reg_val(R3));
        logger->info("\tR4={:#010x}\t R5={:#010x}\t R6={:#010x}\t R7={:#010x}",
                     reg_val(R4),
                     reg_val(R5),
                     reg_val(R6),
                     reg_val(R7));
        logger->info("\tR8={:#010x}\t R9={:#010x}\tR10={:#010x}\t FP={:#010x}",
                     reg_val(R8),
                     reg_val(R9),
                     reg_val(R10),
                     reg_val(FP));
        logger->info("\tIP={:#010x}\t SP={:#010x}\t LR={:#010x}\t PC={:#010x}",
                     reg_val(IP),
                     reg_val(SP),
                     reg_val(LR),
                     reg_val(PC));
        logger->info("\tCPSR={:#032b}", reg_val(CPSR));
    }
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
