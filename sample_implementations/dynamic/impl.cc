#include <cassert>
#include <chrono>
#include <cstdlib>
#include <iostream>
#include <mutex>
#include <sstream>
#include <thread>
#include <unordered_map>

#include <psp2cldr/imp_provider.hpp>

DEFINE_VITA_IMP_NID_EXPORT(88758561, 391B74B7)
{
    DECLARE_VITA_IMP_TYPE(FUNCTION);
    std::cout << "ksceDebugPrintf: entry" << std::endl;

    uint32_t r0 = ctx->thread[RegisterAccessProxy::Register::R0]->r();
    return ctx->handler_call_target_function("strlen", r0)
        ->then([=](uint32_t result, InterruptContext *ctx) {
            std::cout << "ksceDebugPrintf: strlen result=" << result << std::endl;
            return ctx->handler_call_target_function("printf", r0)->then([=](uint32_t result, InterruptContext *ctx) {
                std::cout << "ksceDebugPrintf: printf result=" << result << std::endl;

                // flush
                ctx->coord.proxy().w<uint8_t>(r0, '\n');
                ctx->coord.proxy().w<uint8_t>(r0 + 1, 0);
                return ctx->handler_call_target_function("printf", r0);
            });
        })
        ->then([=](uint32_t result, InterruptContext *ctx) {
            std::cout << "ksceDebugPrintf: printf(\"\\n\") result=" << result << std::endl;
            ctx->thread[RegisterAccessProxy::Register::PC]->w(ctx->thread[RegisterAccessProxy::Register::LR]->r());
            std::cout << "ksceDebugPrintf: exit" << std::endl;
            return std::make_shared<HandlerResult>(0);
        });

    // return ksceDebugPrintf(ctx);
}

#undef _fstat // WATCHOUT: _fstat might be defined somewhere else
DEFINE_VITA_IMP_SYM_EXPORT(_fstat)
{
    DECLARE_VITA_IMP_TYPE(FUNCTION);
    uint32_t fd = ctx->thread[RegisterAccessProxy::Register::R0]->r();
    uint32_t buf = ctx->thread[RegisterAccessProxy::Register::R1]->r();

    return ctx->handler_call_target_function("memset", buf, 0xcc, 0x58)->then([=](uint32_t result, InterruptContext *ctx) {
        uint8_t st[0x58];
        ctx->coord.proxy().copy_out(&st, buf, 0x58);
        for (int i = 0; i < 0x58; i++)
        {
            if (st[i] != 0xcc)
            {
                return std::make_shared<HandlerResult>(1);
            }
        }

        memset(&st, 0, sizeof(st));
        *(uint32_t *)(&st[4]) = 0020000; // st_mode = S_IFCHR;
        ctx->coord.proxy().copy_in(buf, &st, sizeof(st));

        ctx->thread[RegisterAccessProxy::Register::R0]->w(0);
        ctx->thread[RegisterAccessProxy::Register::PC]->w(ctx->thread[RegisterAccessProxy::Register::LR]->r());
        return std::make_shared<HandlerResult>(0);
    });
}

DEFINE_VITA_IMP_SYM_EXPORT(_sbrk)
{
    DECLARE_VITA_IMP_TYPE(FUNCTION);
    auto increment = ctx->thread[RegisterAccessProxy::Register::R0]->r();

    static const uint32_t size = 0x2800000; // 40MB
    static uint32_t begin = ctx->coord.mmap(0, size);
    static uint32_t top = begin;

    if (top + increment < begin + size)
    {
        ctx->thread[RegisterAccessProxy::Register::R0]->w(top);
        top += increment;
    }
    else
    {
        ctx->thread[RegisterAccessProxy::Register::R0]->w(-1);
    }
    ctx->thread[RegisterAccessProxy::Register::PC]->w(ctx->thread[RegisterAccessProxy::Register::LR]->r());
    return std::make_shared<HandlerResult>(0);
}

DEFINE_VITA_IMP_SYM_EXPORT(_close)
{
    DECLARE_VITA_IMP_TYPE(FUNCTION);
    ctx->thread[RegisterAccessProxy::Register::R0]->w(-1);
    ctx->thread[RegisterAccessProxy::Register::PC]->w(ctx->thread[RegisterAccessProxy::Register::LR]->r());
    return std::make_shared<HandlerResult>(0);
}

DEFINE_VITA_IMP_SYM_EXPORT(_isatty)
{
    DECLARE_VITA_IMP_TYPE(FUNCTION);
    ctx->thread[RegisterAccessProxy::Register::R0]->w(1);
    ctx->thread[RegisterAccessProxy::Register::PC]->w(ctx->thread[RegisterAccessProxy::Register::LR]->r());
    return std::make_shared<HandlerResult>(0);
}

DEFINE_VITA_IMP_SYM_EXPORT(_exit)
{
    DECLARE_VITA_IMP_TYPE(FUNCTION);
    ctx->coord.thread_stopall(0);
    return std::make_shared<HandlerResult>(0);
}

#undef _write
DEFINE_VITA_IMP_SYM_EXPORT(_write)
{
    DECLARE_VITA_IMP_TYPE(FUNCTION);
    uint32_t ptr = ctx->thread[RegisterAccessProxy::Register::R1]->r();
    uint32_t len = ctx->thread[RegisterAccessProxy::Register::R2]->r();

    std::stringstream ss;
    for (uint32_t i = 0; i < len; i++)
        ss << ctx->coord.proxy().r<char>(ptr++);

    std::cout << "_write() called: " << ss.str();

    ctx->thread[RegisterAccessProxy::Register::R0]->w(len);
    ctx->thread[RegisterAccessProxy::Register::PC]->w(ctx->thread[RegisterAccessProxy::Register::LR]->r());
    return std::make_shared<HandlerResult>(0);
}

#undef _open
DEFINE_VITA_IMP_SYM_EXPORT(_open)
{
    DECLARE_VITA_IMP_TYPE(FUNCTION); // required for SYM_EXPORT
    uint32_t name = ctx->thread[RegisterAccessProxy::Register::R0]->r();
    uint32_t flags = ctx->thread[RegisterAccessProxy::Register::R1]->r();
    uint32_t mode = ctx->thread[RegisterAccessProxy::Register::R2]->r();

    std::cout << "_open() called: " << ctx->read_str(name) << std::endl;
    ctx->thread[RegisterAccessProxy::Register::R0]->w(-1);
    ctx->thread[RegisterAccessProxy::Register::PC]->w(ctx->thread[RegisterAccessProxy::Register::LR]->r());
    return std::make_shared<HandlerResult>(0);
}

#undef basic_test_variable
DEFINE_VITA_IMP_SYM_EXPORT(basic_test_variable)
{
    DECLARE_VITA_IMP_TYPE(VARIABLE);

    static std::mutex _mutex;
    std::lock_guard guard(_mutex);

    static uint32_t _p_data = 0;

    uint32_t p_var = ctx->thread[RegisterAccessProxy::Register::PC]->r();

    if (_p_data == 0)
    {
        return ctx->handler_call_target_function("malloc", 4)->then([&, p_var](uint32_t result, InterruptContext *ctx) {
            ctx->coord.proxy().w<uint32_t>(result, 42);
            ctx->coord.proxy().w<uint32_t>(p_var, result);
            std::lock_guard guard(_mutex);
            _p_data = result;
            TARGET_RETURN(0);
            HANDLER_RETURN(0);
        });
    }
    else
    {
        ctx->coord.proxy().w<uint32_t>(p_var, _p_data);
        TARGET_RETURN(0);
        HANDLER_RETURN(0);
    }
}

std::unordered_map<uint32_t, std::weak_ptr<ExecutionThread>> threads;
std::mutex threads_lock;

DECLARE_VITA_IMP_NID_EXPORT(CAE9ACE6, C5C11EE7, sceKernelCreateThread)
DEFINE_VITA_IMP_NID_EXPORT(CAE9ACE6, C5C11EE7)
{
    DECLARE_VITA_IMP_TYPE(FUNCTION);

    uint32_t new_pc = PARAM_1;
    uint32_t new_stacksz = PARAM_3;

    static const size_t stack_sz = 0x4000;
    uint32_t sp_base = ctx->coord.mmap(0, stack_sz);
    uint32_t sp = sp_base + stack_sz;
    uint32_t lr = ctx->coord.mmap(0, 0x1000);

    size_t succ_counter = 0;
    auto thread = ctx->coord.thread_create();
    for (auto &la : ctx->load.thread_init_routines)
    {
        (*thread)[RegisterAccessProxy::Register::SP]->w(sp);
        (*thread)[RegisterAccessProxy::Register::LR]->w(lr);

        uint32_t result;
        if (thread->start(la, lr) != ExecutionThread::THREAD_EXECUTION_RESULT::OK || (*thread).join(&result) != ExecutionThread::THREAD_EXECUTION_RESULT::STOP_UNTIL_POINT_HIT || result != 0)
            break;
        if (sp != (*thread)[RegisterAccessProxy::Register::SP]->r())
        {
            std::cout << "sceKernelCreateThread: stack corruption during thread init routines" << std::endl;
            HANDLER_RETURN(1);
        }

        succ_counter++;
    }
    if (succ_counter != ctx->load.thread_init_routines.size())
    {
        std::cout << "sceKernelCreateThread: thread init routines failed" << std::endl;
        HANDLER_RETURN(2);
    }
    ctx->coord.munmap(sp_base, stack_sz);

    (*thread)[RegisterAccessProxy::Register::SP]->w(ctx->coord.mmap(0, new_stacksz) + new_stacksz);
    (*thread)[RegisterAccessProxy::Register::LR]->w(lr);
    (*thread)[RegisterAccessProxy::Register::IP]->w(new_pc); // we will store this in IP, start thread will use this value as PC

    {
        std::lock_guard<std::mutex> guard{threads_lock};
        threads[thread->tid()] = thread;
    }

    TARGET_RETURN(thread->tid());
    HANDLER_RETURN(0);
}

DECLARE_VITA_IMP_NID_EXPORT(CAE9ACE6, F08DE149, sceKernelStartThread)
DEFINE_VITA_IMP_NID_EXPORT(CAE9ACE6, F08DE149)
{
    DECLARE_VITA_IMP_TYPE(FUNCTION);

    uint32_t pp_args = PARAM(ctx, 2);
    {
        std::lock_guard<std::mutex> guard{threads_lock};
        if (auto thread = threads[PARAM(ctx, 0)].lock())
        {
            (*thread)[RegisterAccessProxy::Register::R0]->w(PARAM(ctx, 1));
            (*thread)[RegisterAccessProxy::Register::R1]->w(PARAM(ctx, 2));
            thread->start((*thread)[RegisterAccessProxy::Register::IP]->r(), (*thread)[RegisterAccessProxy::Register::LR]->r());
        }
    }

    TARGET_RETURN(0);
    HANDLER_RETURN(0);
}

DECLARE_VITA_IMP_NID_EXPORT(859A24B1, 1BBDE3D9, sceKernelDeleteThread)
DEFINE_VITA_IMP_NID_EXPORT(859A24B1, 1BBDE3D9)
{
    DECLARE_VITA_IMP_TYPE(FUNCTION);

    uint32_t threadID = PARAM_0;
    if (auto thread = threads[threadID].lock())
    {
        if (thread->state() != ExecutionThread::THREAD_EXECUTION_STATE::RESTARTABLE)
        {
            std::cout << "sceKernelDeleteThread: is the thread in RESTARTABLE state?" << std::endl;
            HANDLER_RETURN(3);
        }

        static const size_t stack_sz = 0x4000;
        uint32_t sp_base = ctx->coord.mmap(0, stack_sz);
        uint32_t sp = sp_base + stack_sz;
        uint32_t lr = (*thread)[RegisterAccessProxy::Register::PC]->r(); // assuming UNTIL_POINT_HIT

        size_t succ_counter = 0;
        for (auto &la : ctx->load.thread_fini_routines)
        {
            (*thread)[RegisterAccessProxy::Register::SP]->w(sp);
            (*thread)[RegisterAccessProxy::Register::LR]->w(lr);

            uint32_t result;
            if (thread->start(la, lr) != ExecutionThread::THREAD_EXECUTION_RESULT::OK || (*thread).join(&result) != ExecutionThread::THREAD_EXECUTION_RESULT::STOP_UNTIL_POINT_HIT || result != 0)
                break;
            if (sp != (*thread)[RegisterAccessProxy::Register::SP]->r())
            {
                std::cout << "sceKernelDeleteThread: stack corruption during thread fini routines" << std::endl;
                HANDLER_RETURN(1);
            }

            succ_counter++;
        }
        if (succ_counter != ctx->load.thread_fini_routines.size())
        {
            std::cout << "sceKernelDeleteThread: thread fini routines failed" << std::endl;
            HANDLER_RETURN(2);
        }
        ctx->coord.munmap(sp_base, stack_sz);
        ctx->coord.munmap(lr, 0x1000);

        {
            std::lock_guard<std::mutex> guard{threads_lock};
            threads.erase(threadID);
        }
        ctx->coord.thread_destory(thread);
    }

    TARGET_RETURN(0);
    HANDLER_RETURN(0);
}

DECLARE_VITA_IMP_NID_EXPORT(859A24B1, 4B675D05, sceKernelDelayThread)
DEFINE_VITA_IMP_NID_EXPORT(859A24B1, 4B675D05)
{
    DECLARE_VITA_IMP_TYPE(FUNCTION);
    std::this_thread::sleep_for(std::chrono::microseconds(PARAM(ctx, 0)));

    TARGET_RETURN(0);
    HANDLER_RETURN(0);
}

VITA_IMP_NID_FORWARD_SYM(CAE9ACE6, FA26BC62, "printf")

#undef __psp2cldr__internal_tls_ctrl
DEFINE_VITA_IMP_SYM_EXPORT(__psp2cldr__internal_tls_ctrl)
{
    DECLARE_VITA_IMP_TYPE(FUNCTION);
    /*
    0: retrieve tls ptr
    1: free tls
    */

    auto ctrl = PARAM_0;
    static std::unordered_map<uint32_t, uint32_t> mapping;
    static std::mutex _mutex;
    auto tid = ctx->thread.tid();

    std::lock_guard guard(_mutex);
    switch (ctrl)
    {
    case 0:
        if (mapping.count(tid) == 0)
            mapping[tid] = ctx->coord.mmap(0, 0x1000);
        TARGET_RETURN(mapping[tid]);
        HANDLER_RETURN(0);
    case 1:
        if (mapping.count(tid) == 0)
        {
            HANDLER_RETURN(1);
        }
        ctx->coord.munmap(mapping[tid], 0x1000);
        mapping.erase(tid);
        TARGET_RETURN(0);
        HANDLER_RETURN(0);
        break;
    default:
        HANDLER_RETURN(2);
    }
}
