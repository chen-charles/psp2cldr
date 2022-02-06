/*
 * Copyright (C) 2021-2022 Jianye Chen
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

#ifndef PSP2CLDR_NATIVEENG_H
#define PSP2CLDR_NATIVEENG_H

#include <atomic>
#include <unordered_map>
#include <unordered_set>

#include <setjmp.h>

#include <pthread.h>
#include <signal.h>
#include <ucontext.h>

#include <psp2cldr/access_proxy.hpp>
#include <psp2cldr/arch.h>
#include <psp2cldr/coordinator.hpp>
#include <psp2cldr/memory_managers.hpp>
#include <psp2cldr/utility/semaphore.hpp>

class NativeEngineARM;
class NativeMemoryAccessProxy : public MemoryAccessProxy
{
  public:
    NativeMemoryAccessProxy(const MemoryTranslator &translator) : m_translator(translator)
    {
    }
    virtual ~NativeMemoryAccessProxy()
    {
    }

    // either during interrupt, or we haven't started
    virtual uint64_t copy_in(uint64_t dest, const void *src, size_t num) const;
    virtual void *copy_out(void *dest, uint64_t src, size_t num) const;

  protected:
    const MemoryTranslator &m_translator;
};

class ExecutionThread_Native;
class RegisterAccessProxy_Native : public RegisterAccessProxy
{
  public:
    RegisterAccessProxy_Native(Register name, const ExecutionThread_Native *engine)
        : RegisterAccessProxy(name), m_engine(engine)
    {
    }
    virtual ~RegisterAccessProxy_Native()
    {
    }

    static inline const std::unordered_map<Register, int> reg_mapping{
        {Register::R0, offsetof(struct sigcontext, arm_r0)},     {Register::R1, offsetof(struct sigcontext, arm_r1)},
        {Register::R2, offsetof(struct sigcontext, arm_r2)},     {Register::R3, offsetof(struct sigcontext, arm_r3)},
        {Register::R4, offsetof(struct sigcontext, arm_r4)},     {Register::R5, offsetof(struct sigcontext, arm_r5)},
        {Register::R6, offsetof(struct sigcontext, arm_r6)},     {Register::R7, offsetof(struct sigcontext, arm_r7)},
        {Register::R8, offsetof(struct sigcontext, arm_r8)},     {Register::R9, offsetof(struct sigcontext, arm_r9)},
        {Register::R10, offsetof(struct sigcontext, arm_r10)},   {Register::R11, offsetof(struct sigcontext, arm_fp)},
        {Register::R12, offsetof(struct sigcontext, arm_ip)},    {Register::R13, offsetof(struct sigcontext, arm_sp)},
        {Register::R14, offsetof(struct sigcontext, arm_lr)},    {Register::R15, offsetof(struct sigcontext, arm_pc)},
        {Register::CPSR, offsetof(struct sigcontext, arm_cpsr)},
    };

    virtual uint32_t w(uint32_t value);
    virtual uint32_t r() const;

  protected:
    const ExecutionThread_Native *m_engine;
};

class InterruptContext;
class NativeEngineARM;

class ExecutionThread_Native : public ExecutionThread
{
  public:
    ExecutionThread_Native(ExecutionCoordinator &coordinator);
    virtual ~ExecutionThread_Native();

    virtual void register_interrupt_callback(
        std::function<void(ExecutionCoordinator &, ExecutionThread &, uint32_t)> callback)
    {
        m_intr_callback = callback;
    }

    virtual const std::atomic<THREAD_EXECUTION_STATE> &state() const
    {
        return m_state;
    }

    virtual THREAD_EXECUTION_RESULT start(uint32_t from, uint32_t until);
    virtual THREAD_EXECUTION_RESULT join(uint32_t *retval);
    virtual void stop(uint32_t retval);
    virtual pthread_t pthread_id() const
    {
        return m_thread;
    }

    virtual void panic(int code = 0, LoadContext *load = nullptr);

  public:
    virtual std::shared_ptr<RegisterAccessProxy> operator[](RegisterAccessProxy::Register name)
    {
        return std::make_shared<RegisterAccessProxy_Native>(name, this);
    }

    virtual std::shared_ptr<const RegisterAccessProxy> operator[](RegisterAccessProxy::Register name) const
    {
        return std::make_shared<const RegisterAccessProxy_Native>(name, this);
    }

  public:
    ExecutionCoordinator &m_coord;

    std::function<void(ExecutionCoordinator &, ExecutionThread &, uint32_t)> m_intr_callback = {};

    semaphore m_thread_lock{1};
    bool m_thread_is_valid{false};
    pthread_t m_thread;
    std::atomic<bool> m_stoppable{false};
    std::atomic<bool> m_stop_called{false};
    std::atomic<bool> m_handling_interrupt{false};
    uint32_t m_until_point_instr_backup{0};

    std::atomic<THREAD_EXECUTION_STATE> m_state{THREAD_EXECUTION_STATE::UNSTARTED};
    std::atomic<bool> m_started{false};
    std::atomic<THREAD_EXECUTION_RESULT> m_result;

    std::mutex join_lock;

    std::atomic<uint32_t> m_target_until_point;
    mutable ucontext_t m_target_ctx;
    sigjmp_buf m_return_ctx;
    siginfo_t m_target_siginfo;

    stack_t m_old_ss;
    char *m_sigstack = nullptr;
    size_t m_szsigstack = 4 * SIGSTKSZ;
};
static_assert(std::atomic<bool>::is_always_lock_free);
static_assert(std::atomic<uint32_t>::is_always_lock_free);

class NativeEngineARM : public ExecutionCoordinator
{
  public:
    NativeEngineARM();
    virtual ~NativeEngineARM();

    virtual NativeMemoryAccessProxy &proxy() const
    {
        return static_proxy;
    }

    virtual uintptr_t mmap(uintptr_t preferred, size_t length);
    virtual int munmap(uintptr_t addr, size_t length);

    [[nodiscard]] virtual std::shared_ptr<ExecutionThread> thread_create();
    virtual int thread_destroy(std::weak_ptr<ExecutionThread> thread);
    virtual void thread_joinall();
    virtual void thread_stopall(int retval = 0);

    virtual void panic(int code = 0, LoadContext *load = nullptr);

    virtual void register_interrupt_callback(
        std::function<void(ExecutionCoordinator &, ExecutionThread &, uint32_t)> callback)
    {
        m_intr_callback = callback;
    }

  protected:
    MemoryTranslator m_translator;
    MemoryAllocator m_allocator;
    std::recursive_mutex m_memory_lock;
    mutable NativeMemoryAccessProxy static_proxy{m_translator};

  protected:
    std::function<void(ExecutionCoordinator &, ExecutionThread &, uint32_t)> m_intr_callback = {};
    friend void _sig_handler(int sig, siginfo_t *info, void *ucontext);
    friend void *thread_bootstrap(struct thread_bootstrap_args *args);

  protected:
    std::mutex m_threads_lock;
    std::unordered_set<std::shared_ptr<ExecutionThread>> m_threads;

  protected:
    struct sigaction m_old_action_ill;
    struct sigaction m_old_action_segv;
    struct sigaction m_old_action_int;
    struct sigaction m_old_action_targetinit;
    struct sigaction m_old_action_targetreturn;
    stack_t m_old_ss;
    char *m_sigstack = nullptr;
    size_t m_szsigstack = 4 * SIGSTKSZ;
};

#define Coordinator_Impl NativeEngineARM

#endif
