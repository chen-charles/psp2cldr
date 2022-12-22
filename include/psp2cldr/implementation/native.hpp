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
	{}
	virtual ~NativeMemoryAccessProxy()
	{}

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
	RegisterAccessProxy_Native(Register name, const ExecutionThread_Native *engine) : RegisterAccessProxy(name), m_engine(engine)
	{}
	virtual ~RegisterAccessProxy_Native()
	{}

	static inline const std::unordered_map<Register, int> reg_mapping{
		{Register::R0, offsetof(struct ucontext_t, uc_mcontext) + offsetof(struct sigcontext, arm_r0)},
		{Register::R1, offsetof(struct ucontext_t, uc_mcontext) + offsetof(struct sigcontext, arm_r1)},
		{Register::R2, offsetof(struct ucontext_t, uc_mcontext) + offsetof(struct sigcontext, arm_r2)},
		{Register::R3, offsetof(struct ucontext_t, uc_mcontext) + offsetof(struct sigcontext, arm_r3)},
		{Register::R4, offsetof(struct ucontext_t, uc_mcontext) + offsetof(struct sigcontext, arm_r4)},
		{Register::R5, offsetof(struct ucontext_t, uc_mcontext) + offsetof(struct sigcontext, arm_r5)},
		{Register::R6, offsetof(struct ucontext_t, uc_mcontext) + offsetof(struct sigcontext, arm_r6)},
		{Register::R7, offsetof(struct ucontext_t, uc_mcontext) + offsetof(struct sigcontext, arm_r7)},
		{Register::R8, offsetof(struct ucontext_t, uc_mcontext) + offsetof(struct sigcontext, arm_r8)},
		{Register::R9, offsetof(struct ucontext_t, uc_mcontext) + offsetof(struct sigcontext, arm_r9)},
		{Register::R10, offsetof(struct ucontext_t, uc_mcontext) + offsetof(struct sigcontext, arm_r10)},
		{Register::R11, offsetof(struct ucontext_t, uc_mcontext) + offsetof(struct sigcontext, arm_fp)},
		{Register::R12, offsetof(struct ucontext_t, uc_mcontext) + offsetof(struct sigcontext, arm_ip)},
		{Register::R13, offsetof(struct ucontext_t, uc_mcontext) + offsetof(struct sigcontext, arm_sp)},
		{Register::R14, offsetof(struct ucontext_t, uc_mcontext) + offsetof(struct sigcontext, arm_lr)},
		{Register::R15, offsetof(struct ucontext_t, uc_mcontext) + offsetof(struct sigcontext, arm_pc)},
		{Register::CPSR, offsetof(struct ucontext_t, uc_mcontext) + offsetof(struct sigcontext, arm_cpsr)},
		{Register::FPSCR, offsetof(struct ucontext_t, uc_regspace) + sizeof(uint32_t) * 2 + sizeof(uint64_t) * 32} /* see vfp_sigframe */,

#pragma region SIMD
		{Register::Q0, offsetof(struct ucontext_t, uc_regspace) + sizeof(uint32_t) * 2 + sizeof(uint64_t) * 2 * 0},
		{Register::Q1, offsetof(struct ucontext_t, uc_regspace) + sizeof(uint32_t) * 2 + sizeof(uint64_t) * 2 * 1},
		{Register::Q2, offsetof(struct ucontext_t, uc_regspace) + sizeof(uint32_t) * 2 + sizeof(uint64_t) * 2 * 2},
		{Register::Q3, offsetof(struct ucontext_t, uc_regspace) + sizeof(uint32_t) * 2 + sizeof(uint64_t) * 2 * 3},
		{Register::Q4, offsetof(struct ucontext_t, uc_regspace) + sizeof(uint32_t) * 2 + sizeof(uint64_t) * 2 * 4},
		{Register::Q5, offsetof(struct ucontext_t, uc_regspace) + sizeof(uint32_t) * 2 + sizeof(uint64_t) * 2 * 5},
		{Register::Q6, offsetof(struct ucontext_t, uc_regspace) + sizeof(uint32_t) * 2 + sizeof(uint64_t) * 2 * 6},
		{Register::Q7, offsetof(struct ucontext_t, uc_regspace) + sizeof(uint32_t) * 2 + sizeof(uint64_t) * 2 * 7},
		{Register::Q8, offsetof(struct ucontext_t, uc_regspace) + sizeof(uint32_t) * 2 + sizeof(uint64_t) * 2 * 8},
		{Register::Q9, offsetof(struct ucontext_t, uc_regspace) + sizeof(uint32_t) * 2 + sizeof(uint64_t) * 2 * 9},
		{Register::Q10, offsetof(struct ucontext_t, uc_regspace) + sizeof(uint32_t) * 2 + sizeof(uint64_t) * 2 * 10},
		{Register::Q11, offsetof(struct ucontext_t, uc_regspace) + sizeof(uint32_t) * 2 + sizeof(uint64_t) * 2 * 11},
		{Register::Q12, offsetof(struct ucontext_t, uc_regspace) + sizeof(uint32_t) * 2 + sizeof(uint64_t) * 2 * 12},
		{Register::Q13, offsetof(struct ucontext_t, uc_regspace) + sizeof(uint32_t) * 2 + sizeof(uint64_t) * 2 * 13},
		{Register::Q14, offsetof(struct ucontext_t, uc_regspace) + sizeof(uint32_t) * 2 + sizeof(uint64_t) * 2 * 14},
		{Register::Q15, offsetof(struct ucontext_t, uc_regspace) + sizeof(uint32_t) * 2 + sizeof(uint64_t) * 2 * 15},

		{Register::D0, offsetof(struct ucontext_t, uc_regspace) + sizeof(uint32_t) * 2 + sizeof(uint64_t) * 0},
		{Register::D1, offsetof(struct ucontext_t, uc_regspace) + sizeof(uint32_t) * 2 + sizeof(uint64_t) * 1},
		{Register::D2, offsetof(struct ucontext_t, uc_regspace) + sizeof(uint32_t) * 2 + sizeof(uint64_t) * 2},
		{Register::D3, offsetof(struct ucontext_t, uc_regspace) + sizeof(uint32_t) * 2 + sizeof(uint64_t) * 3},
		{Register::D4, offsetof(struct ucontext_t, uc_regspace) + sizeof(uint32_t) * 2 + sizeof(uint64_t) * 4},
		{Register::D5, offsetof(struct ucontext_t, uc_regspace) + sizeof(uint32_t) * 2 + sizeof(uint64_t) * 5},
		{Register::D6, offsetof(struct ucontext_t, uc_regspace) + sizeof(uint32_t) * 2 + sizeof(uint64_t) * 6},
		{Register::D7, offsetof(struct ucontext_t, uc_regspace) + sizeof(uint32_t) * 2 + sizeof(uint64_t) * 7},
		{Register::D8, offsetof(struct ucontext_t, uc_regspace) + sizeof(uint32_t) * 2 + sizeof(uint64_t) * 8},
		{Register::D9, offsetof(struct ucontext_t, uc_regspace) + sizeof(uint32_t) * 2 + sizeof(uint64_t) * 9},
		{Register::D10, offsetof(struct ucontext_t, uc_regspace) + sizeof(uint32_t) * 2 + sizeof(uint64_t) * 10},
		{Register::D11, offsetof(struct ucontext_t, uc_regspace) + sizeof(uint32_t) * 2 + sizeof(uint64_t) * 11},
		{Register::D12, offsetof(struct ucontext_t, uc_regspace) + sizeof(uint32_t) * 2 + sizeof(uint64_t) * 12},
		{Register::D13, offsetof(struct ucontext_t, uc_regspace) + sizeof(uint32_t) * 2 + sizeof(uint64_t) * 13},
		{Register::D14, offsetof(struct ucontext_t, uc_regspace) + sizeof(uint32_t) * 2 + sizeof(uint64_t) * 14},
		{Register::D15, offsetof(struct ucontext_t, uc_regspace) + sizeof(uint32_t) * 2 + sizeof(uint64_t) * 15},
		{Register::D16, offsetof(struct ucontext_t, uc_regspace) + sizeof(uint32_t) * 2 + sizeof(uint64_t) * 16},
		{Register::D17, offsetof(struct ucontext_t, uc_regspace) + sizeof(uint32_t) * 2 + sizeof(uint64_t) * 17},
		{Register::D18, offsetof(struct ucontext_t, uc_regspace) + sizeof(uint32_t) * 2 + sizeof(uint64_t) * 18},
		{Register::D19, offsetof(struct ucontext_t, uc_regspace) + sizeof(uint32_t) * 2 + sizeof(uint64_t) * 19},
		{Register::D20, offsetof(struct ucontext_t, uc_regspace) + sizeof(uint32_t) * 2 + sizeof(uint64_t) * 20},
		{Register::D21, offsetof(struct ucontext_t, uc_regspace) + sizeof(uint32_t) * 2 + sizeof(uint64_t) * 21},
		{Register::D22, offsetof(struct ucontext_t, uc_regspace) + sizeof(uint32_t) * 2 + sizeof(uint64_t) * 22},
		{Register::D23, offsetof(struct ucontext_t, uc_regspace) + sizeof(uint32_t) * 2 + sizeof(uint64_t) * 23},
		{Register::D24, offsetof(struct ucontext_t, uc_regspace) + sizeof(uint32_t) * 2 + sizeof(uint64_t) * 24},
		{Register::D25, offsetof(struct ucontext_t, uc_regspace) + sizeof(uint32_t) * 2 + sizeof(uint64_t) * 25},
		{Register::D26, offsetof(struct ucontext_t, uc_regspace) + sizeof(uint32_t) * 2 + sizeof(uint64_t) * 26},
		{Register::D27, offsetof(struct ucontext_t, uc_regspace) + sizeof(uint32_t) * 2 + sizeof(uint64_t) * 27},
		{Register::D28, offsetof(struct ucontext_t, uc_regspace) + sizeof(uint32_t) * 2 + sizeof(uint64_t) * 28},
		{Register::D29, offsetof(struct ucontext_t, uc_regspace) + sizeof(uint32_t) * 2 + sizeof(uint64_t) * 29},
		{Register::D30, offsetof(struct ucontext_t, uc_regspace) + sizeof(uint32_t) * 2 + sizeof(uint64_t) * 30},
		{Register::D31, offsetof(struct ucontext_t, uc_regspace) + sizeof(uint32_t) * 2 + sizeof(uint64_t) * 31},

		{Register::S0, offsetof(struct ucontext_t, uc_regspace) + sizeof(uint32_t) * 2 + sizeof(uint32_t) * 0},
		{Register::S1, offsetof(struct ucontext_t, uc_regspace) + sizeof(uint32_t) * 2 + sizeof(uint32_t) * 1},
		{Register::S2, offsetof(struct ucontext_t, uc_regspace) + sizeof(uint32_t) * 2 + sizeof(uint32_t) * 2},
		{Register::S3, offsetof(struct ucontext_t, uc_regspace) + sizeof(uint32_t) * 2 + sizeof(uint32_t) * 3},
		{Register::S4, offsetof(struct ucontext_t, uc_regspace) + sizeof(uint32_t) * 2 + sizeof(uint32_t) * 4},
		{Register::S5, offsetof(struct ucontext_t, uc_regspace) + sizeof(uint32_t) * 2 + sizeof(uint32_t) * 5},
		{Register::S6, offsetof(struct ucontext_t, uc_regspace) + sizeof(uint32_t) * 2 + sizeof(uint32_t) * 6},
		{Register::S7, offsetof(struct ucontext_t, uc_regspace) + sizeof(uint32_t) * 2 + sizeof(uint32_t) * 7},
		{Register::S8, offsetof(struct ucontext_t, uc_regspace) + sizeof(uint32_t) * 2 + sizeof(uint32_t) * 8},
		{Register::S9, offsetof(struct ucontext_t, uc_regspace) + sizeof(uint32_t) * 2 + sizeof(uint32_t) * 9},
		{Register::S10, offsetof(struct ucontext_t, uc_regspace) + sizeof(uint32_t) * 2 + sizeof(uint32_t) * 10},
		{Register::S11, offsetof(struct ucontext_t, uc_regspace) + sizeof(uint32_t) * 2 + sizeof(uint32_t) * 11},
		{Register::S12, offsetof(struct ucontext_t, uc_regspace) + sizeof(uint32_t) * 2 + sizeof(uint32_t) * 12},
		{Register::S13, offsetof(struct ucontext_t, uc_regspace) + sizeof(uint32_t) * 2 + sizeof(uint32_t) * 13},
		{Register::S14, offsetof(struct ucontext_t, uc_regspace) + sizeof(uint32_t) * 2 + sizeof(uint32_t) * 14},
		{Register::S15, offsetof(struct ucontext_t, uc_regspace) + sizeof(uint32_t) * 2 + sizeof(uint32_t) * 15},
		{Register::S16, offsetof(struct ucontext_t, uc_regspace) + sizeof(uint32_t) * 2 + sizeof(uint32_t) * 16},
		{Register::S17, offsetof(struct ucontext_t, uc_regspace) + sizeof(uint32_t) * 2 + sizeof(uint32_t) * 17},
		{Register::S18, offsetof(struct ucontext_t, uc_regspace) + sizeof(uint32_t) * 2 + sizeof(uint32_t) * 18},
		{Register::S19, offsetof(struct ucontext_t, uc_regspace) + sizeof(uint32_t) * 2 + sizeof(uint32_t) * 19},
		{Register::S20, offsetof(struct ucontext_t, uc_regspace) + sizeof(uint32_t) * 2 + sizeof(uint32_t) * 20},
		{Register::S21, offsetof(struct ucontext_t, uc_regspace) + sizeof(uint32_t) * 2 + sizeof(uint32_t) * 21},
		{Register::S22, offsetof(struct ucontext_t, uc_regspace) + sizeof(uint32_t) * 2 + sizeof(uint32_t) * 22},
		{Register::S23, offsetof(struct ucontext_t, uc_regspace) + sizeof(uint32_t) * 2 + sizeof(uint32_t) * 23},
		{Register::S24, offsetof(struct ucontext_t, uc_regspace) + sizeof(uint32_t) * 2 + sizeof(uint32_t) * 24},
		{Register::S25, offsetof(struct ucontext_t, uc_regspace) + sizeof(uint32_t) * 2 + sizeof(uint32_t) * 25},
		{Register::S26, offsetof(struct ucontext_t, uc_regspace) + sizeof(uint32_t) * 2 + sizeof(uint32_t) * 26},
		{Register::S27, offsetof(struct ucontext_t, uc_regspace) + sizeof(uint32_t) * 2 + sizeof(uint32_t) * 27},
		{Register::S28, offsetof(struct ucontext_t, uc_regspace) + sizeof(uint32_t) * 2 + sizeof(uint32_t) * 28},
		{Register::S29, offsetof(struct ucontext_t, uc_regspace) + sizeof(uint32_t) * 2 + sizeof(uint32_t) * 29},
		{Register::S30, offsetof(struct ucontext_t, uc_regspace) + sizeof(uint32_t) * 2 + sizeof(uint32_t) * 30},
		{Register::S31, offsetof(struct ucontext_t, uc_regspace) + sizeof(uint32_t) * 2 + sizeof(uint32_t) * 31},

#pragma endregion SIMD
	};

#pragma region SIMD
	virtual Float128 w_Q(Float128 value) override;
	virtual Float128 r_Q() const override;

	virtual uint64_t w_D(uint64_t value) override;
	virtual uint64_t r_D() const override;

	virtual uint32_t w_S(uint32_t value) override;
	virtual uint32_t r_S() const override;
#pragma endregion SIMD

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

	virtual void register_interrupt_callback(std::function<void(ExecutionCoordinator &, ExecutionThread &, uint32_t)> callback)
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

	mutable semaphore m_exitwait{0};
	mutable std::mutex m_thread_lock;
	bool m_thread_is_valid{false};
	pthread_t m_thread;
	std::atomic<bool> m_stoppable{false};
	std::atomic<bool> m_stop_called{false};
	std::atomic<bool> m_handling_interrupt{false};
	uint32_t m_until_point_instr_backup{0};

	std::atomic<THREAD_EXECUTION_STATE> m_state{THREAD_EXECUTION_STATE::UNSTARTED};
	std::atomic<bool> m_started{false};
	std::atomic<THREAD_EXECUTION_RESULT> m_result;

	std::atomic<uint32_t> m_target_until_point;
	mutable ucontext_t m_target_ctx;
	sigjmp_buf m_return_ctx;
	siginfo_t m_target_siginfo;

	stack_t m_old_ss;
	char *m_sigstack = nullptr;
	size_t m_szsigstack = 4 * SIGSTKSZ;

	std::atomic<uint32_t> m_sigill_request{0};
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

	virtual void register_interrupt_callback(std::function<void(ExecutionCoordinator &, ExecutionThread &, uint32_t)> callback)
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
	stack_t m_old_ss;
	char *m_sigstack = nullptr;
	size_t m_szsigstack = 4 * SIGSTKSZ;
};

#define Coordinator_Impl NativeEngineARM

#endif
