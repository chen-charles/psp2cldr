/*
 * Copyright (C) 2021-2022 Jianye Chen
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

#include <cassert>
#include <unistd.h>

#include <psp2cldr/context.hpp>
#include <psp2cldr/implementation/logger.hpp>
#include <psp2cldr/implementation/native.hpp>
#include <psp2cldr/utility/semaphore.hpp>

#ifdef __linux__
#include <sys/syscall.h> // syscall(SYS_gettid)
#endif

pthread_key_t thread_init_key;
pthread_key_t thread_obj_key;
static bool SIGINT_queued = false;
static NativeEngineARM *g_coord = nullptr;

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
	// https://lists.gnu.org/archive/html/qemu-devel/2021-04/msg02211.html
	if (name() == Register::PC)
	{
		if (TESTBIT(value, 0))
		{
			clearbit(&value, 0);
			setbit(&m_engine->m_target_ctx.uc_mcontext.arm_cpsr, 5);
		}
		else
		{
			clearbit(&m_engine->m_target_ctx.uc_mcontext.arm_cpsr, 5);
		}
	}

	*(unsigned long *)((char *)(&(m_engine->m_target_ctx)) + reg_mapping.at(name())) = value; // implementation specific, assuming glibc
	return value;
}

uint32_t RegisterAccessProxy_Native::r() const
{
	const uint32_t value = *(unsigned long *)((char *)(&(m_engine->m_target_ctx)) + reg_mapping.at(name()));
	if (name() == Register::PC)
	{
		return CLEARBIT(value, 0);
	}
	return value;
}

Float128 RegisterAccessProxy_Native::w_Q(Float128 value)
{
	return *(Float128 *)((char *)(&(m_engine->m_target_ctx)) + reg_mapping.at(name())) = value; // implementation specific
}

Float128 RegisterAccessProxy_Native::r_Q() const
{
	return *(Float128 *)((char *)(&(m_engine->m_target_ctx)) + reg_mapping.at(name()));
}

uint64_t RegisterAccessProxy_Native::w_D(uint64_t value)
{
	return *(uint64_t *)((char *)(&(m_engine->m_target_ctx)) + reg_mapping.at(name())) = value; // implementation specific
}

uint64_t RegisterAccessProxy_Native::r_D() const
{
	return *(uint64_t *)((char *)(&(m_engine->m_target_ctx)) + reg_mapping.at(name()));
}

uint32_t RegisterAccessProxy_Native::w_S(uint32_t value)
{
	return *(uint32_t *)((char *)(&(m_engine->m_target_ctx)) + reg_mapping.at(name())) = value; // implementation specific
}

uint32_t RegisterAccessProxy_Native::r_S() const
{
	return *(uint32_t *)((char *)(&(m_engine->m_target_ctx)) + reg_mapping.at(name()));
}

void _sig_handler(int sig, siginfo_t *info, void *ucontext)
{
	assert(sig == SIGILL);
	if (sig != info->si_signo)
	{
		raise(SIGTRAP);
	}
	assert(sig == info->si_signo);

	auto ctx = reinterpret_cast<ucontext_t *>(ucontext);

	ExecutionThread_Native *exec_thread = nullptr;

	bool is_stop = false;
	if (info->si_code == SI_QUEUE)
	{
		assert(sig == SIGILL);
		is_stop = true;
	}

	if (!g_coord)
	{
		// ??
		raise(SIGTRAP);
	}

	// https://www.gnu.org/software/libc/manual/html_node/Thread_002dspecific-Data.html
	exec_thread = static_cast<ExecutionThread_Native *>(pthread_getspecific(thread_init_key));
	if (!exec_thread)
	{
		exec_thread = static_cast<ExecutionThread_Native *>(pthread_getspecific(thread_obj_key));
	}

	if (!exec_thread)
	{
		if (is_stop) // the thread is already dead, ignore the stop request
			return;

		if (sig == SIGINT)
		{
			if (!SIGINT_queued)
				SIGINT_queued = true;
			return;
		}

		LOG(CRITICAL, "did not find an exec_thread, falling back to default signal action, PC={:#010x}, LR={:#010x}", ctx->uc_mcontext.arm_pc,
			ctx->uc_mcontext.arm_lr);
		switch (sig)
		{
		case SIGSEGV:
			if (g_coord->m_old_action_segv.sa_flags & SA_SIGINFO)
				(g_coord->m_old_action_segv.sa_sigaction)(sig, info, ucontext);
			else
				(g_coord->m_old_action_segv.sa_handler)(sig);
			return;
		case SIGILL:
			if (g_coord->m_old_action_ill.sa_flags & SA_SIGINFO)
				(g_coord->m_old_action_ill.sa_sigaction)(sig, info, ucontext);
			else
				(g_coord->m_old_action_ill.sa_handler)(sig);
			return;
		default:
			throw std::logic_error("unexpected signal");
		}
	}

	switch (exec_thread->m_sigill_request)
	{
	case 0:
		break;
	case 1: // TARGET_INIT
		clearbit(&ctx->uc_mcontext.arm_pc, 0);
		exec_thread->m_target_ctx = *ctx;

		exec_thread->m_sigill_request = 0;

		// CPSR.T: bit 5
		if (TESTBIT(ctx->uc_mcontext.arm_cpsr, 5))
		{
			ctx->uc_mcontext.arm_pc += 2;
		}
		else
		{
			ctx->uc_mcontext.arm_pc += 4;
		}
		return;
	case 2: // TARGET_RETURN
		if (!exec_thread->m_started)
		{
			assert(false);
			return;
		}

		assert(exec_thread->m_target_ctx.uc_regspace[0] != 0);
		*ctx = exec_thread->m_target_ctx;

		// Jazelle, see DDI0406C A.2.5.1
		if (TESTBIT(ctx->uc_mcontext.arm_cpsr, 24))
		{
			clearbit(&ctx->uc_mcontext.arm_cpsr, 24);
		}
		assert(!TESTBIT(ctx->uc_mcontext.arm_pc, 0));

		exec_thread->m_sigill_request = 0;
		return;
	}

	if (!exec_thread->m_started)
	{
		LOG(CRITICAL, "signal({}): thread has not started", exec_thread->tid());
		InterruptContext::GLOBAL_PANIC_LOCK.lock();
		assert(false);
		_exit(0xc);
	}

	if (exec_thread->m_handling_interrupt)
	{
		/**
		 * how do we interrupt/stop() when the thread is currently in a provider function?
		 * we will likely corrupt stuff...
		 */
		if (exec_thread->m_stop_called)
		{
			// do nothing and return
			// worst-case we will stop at the next interrupt entry, better than crashing
			return;
		}

		InterruptContext::GLOBAL_PANIC_LOCK.lock();
		switch (sig)
		{
		case SIGSEGV:
			if (g_coord->m_old_action_segv.sa_flags & SA_SIGINFO)
				(g_coord->m_old_action_segv.sa_sigaction)(sig, info, ucontext);
			else
				(g_coord->m_old_action_segv.sa_handler)(sig);
			return;
		case SIGILL:
			if (g_coord->m_old_action_ill.sa_flags & SA_SIGINFO)
				(g_coord->m_old_action_ill.sa_sigaction)(sig, info, ucontext);
			else
				(g_coord->m_old_action_ill.sa_handler)(sig);
			return;
		default:
			throw std::logic_error("unexpected signal");
		}
	}

	if (ctx->uc_stack.ss_sp != exec_thread->m_sigstack)
	{
		InterruptContext::GLOBAL_PANIC_LOCK.lock();
		assert(false);
		_exit(0xf);
	}

	assert(ctx->uc_stack.ss_sp == exec_thread->m_sigstack);
	assert(ctx->uc_stack.ss_size == exec_thread->m_szsigstack);

	clearbit(&ctx->uc_mcontext.arm_pc, 0);
	exec_thread->m_handling_interrupt = true;
	exec_thread->m_target_ctx = *ctx;
	exec_thread->m_target_siginfo = *info;

	siglongjmp(exec_thread->m_return_ctx, 1);
}

void _trigger_sigill()
{
	std::atomic_signal_fence(std::memory_order_seq_cst);
	__asm__("udf #0xff");
	std::atomic_signal_fence(std::memory_order_seq_cst);
}

static inline void _execute_recover_until_point(uintptr_t until, uint32_t backup, MemoryAccessProxy &proxy)
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

ExecutionThread_Native::ExecutionThread_Native(ExecutionCoordinator &coord) : m_coord(coord)
{
	m_sigstack = (char *)std::aligned_alloc(16, m_szsigstack);
	assert(m_sigstack);

	// cannot use thread_obj_key here, we could be nested inside provider function
	// which will overwrite the callers provider key
	pthread_setspecific(thread_init_key, this);
	m_sigill_request = 1;
	_trigger_sigill();
	if (m_sigill_request != 0)
		throw std::runtime_error("ExecutionThread_Native initialization failed");
	pthread_setspecific(thread_init_key, NULL);
}

ExecutionThread_Native::~ExecutionThread_Native()
{
	assert(!m_started);
	assert(!m_thread_is_valid);
	free(m_sigstack);
}

struct thread_bootstrap_args
{
	ExecutionThread_Native *thread;

	semaphore barrier;

	ExecutionThread::THREAD_EXECUTION_RESULT start_result;
};

/**
 * @TODO: expose VFP registers from RegisterAccessProxy
 */
#if 0
struct user_vfp
{
    unsigned long long fpregs[32];
    unsigned long fpscr;
};

struct user_vfp_exc
{
    unsigned long fpexc;
    unsigned long fpinst;
    unsigned long fpinst2;
};

struct vfp_sigframe
{
    unsigned long magic;
    unsigned long size;
    user_vfp ufp;
    user_vfp_exc ufp_exc;
} __attribute__((__aligned__(8)));
#endif

void thread_handle_signal()
{
	ExecutionThread_Native *thread = static_cast<ExecutionThread_Native *>(pthread_getspecific(thread_obj_key));
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
		LOG(TRACE, "execute({}): handling interrupt si_signo={:#x} pc={:#010x} si_addr={:#010x} si_code={}", thread->tid(), thread->m_target_siginfo.si_signo,
			pc, (uint32_t)thread->m_target_siginfo.si_addr, (uint32_t)thread->m_target_siginfo.si_code);
		if (thread->m_target_siginfo.si_signo == SIGILL || thread->m_target_siginfo.si_signo == SIGSEGV || thread->m_target_siginfo.si_signo == SIGINT ||
			SIGINT_queued)
		{
			if (SIGINT_queued)
			{
				LOG(CRITICAL, "SIGINT was queued, passing to intr_callback");
				thread->m_intr_callback(thread->m_coord, *thread, SIGINT);
				SIGINT_queued = false;
			}

			thread->m_intr_callback(thread->m_coord, *thread, thread->m_target_siginfo.si_signo);

			// make sure we don't accidentally change thread_obj_key in a nested scenario
			assert(pthread_getspecific(thread_obj_key) == thread);

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

				/**
				 * setcontext to ucp "being passed as an argument to a signal handler" is unspecified behavior
				 * since SUSv2, https://pubs.opengroup.org/onlinepubs/007908799/xsh/getcontext.html
				 *
				 * This is unfortunately what happened here:
				 * setcontext is not expecting the same format as what the signal handler gave to us,
				 * leading to VFP registers trashed unintentionally
				 * https://sourceware.org/git/?p=glibc.git;a=commit;f=sysdeps/unix/sysv/linux/arm/setcontext.S;h=6dcf80c78273c5e0bdcacaf64a9b34fd930b405f
				 *
				 * The kernel sets up uc_regspace with MAGIC and STORAGE_SIZE instead,
				 * https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=12c3dca25d2fa17a101de0d80bf3f238b1cecbae
				 * https://github.com/torvalds/linux/blob/1f2cfdd349b7647f438c1e552dc1b983da86d830/arch/arm/include/asm/ucontext.h#L34
				 */
				// setcontext(&thread->m_target_ctx); // no return, or it failed

				std::atomic_signal_fence(std::memory_order_seq_cst);
				assert(pthread_getspecific(thread_obj_key) == thread);
				thread->m_sigill_request = 2;
				_trigger_sigill();
				LOG(CRITICAL, "execute({}): _trigger_sigill returned at an expected location", thread->tid());
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

		result = ExecutionThread::THREAD_EXECUTION_RESULT::STOP_UNTIL_POINT_HIT;
	}

_done:
	// we need to be able to call pthread_kill to stop()
	// but we can't use m_thread_lock because if the thread is currently being joined, we won't be able to get that lock
	// so we need another semaphore to signal whether it is safe to exit this thread
	thread->m_exitwait.acquire();

	pthread_setspecific(thread_obj_key, NULL);
	// we must not trigger any interrupts to this thread after this point

	_execute_recover_until_point(thread->m_target_until_point, thread->m_until_point_instr_backup, thread->m_coord.proxy());

	thread->m_result = result;
	thread->m_state = ExecutionThread::THREAD_EXECUTION_STATE::RESTARTABLE;
	thread->m_handling_interrupt = false;
	thread->m_started = false;

	thread->m_stop_called = false;

#ifdef __linux__
	LOG(TRACE, "execute({}, {}): thread exit", thread->tid(), (uintptr_t)syscall(SYS_gettid));
#endif

	return;
}

void *thread_bootstrap(thread_bootstrap_args *args)
{
	ExecutionThread_Native *thread = args->thread;
	ExecutionThread::THREAD_EXECUTION_RESULT result = ExecutionThread::THREAD_EXECUTION_RESULT::START_FAILED;

	stack_t ss;
	ss.ss_size = thread->m_szsigstack;
	ss.ss_flags = 0;
	ss.ss_sp = (void *)thread->m_sigstack;
	if (sigaltstack(&ss, &thread->m_old_ss) != 0)
		throw std::runtime_error("unrecoverable failure: sigaltstack");

	{
		/**
		 * the linux kernel calls the signal handler with the actual kernel context frame's ucontext structure
		 * thus, if we attempt to restore to target_ctx acquired outside of this thread, we would effectively corrupt
		 * that structure, and since sigaltstack information is stored there, the call to change signal stack from this
		 * thread will have no effects.
		 *
		 * let's acquire a copy of ucontext_t from this thread directly and reapply the interested fields from the dummy we setup outside
		 */
		pthread_setspecific(thread_init_key, thread);

		ucontext_t m_target_ctx_copy = thread->m_target_ctx;
		thread->m_sigill_request = 1;
		_trigger_sigill();
		if (thread->m_sigill_request == 0)
		{
			thread->m_target_ctx.uc_mcontext = m_target_ctx_copy.uc_mcontext;
		}
		else
		{
			throw std::runtime_error("unrecoverable failure: _trigger_sigill(1)");
		}

		pthread_setspecific(thread_init_key, NULL);
	}

#ifndef NDEBUG
	assert(sigaltstack(nullptr, &ss) == 0);
	assert(ss.ss_sp == (void *)thread->m_sigstack);
#endif

#ifdef __linux__
	LOG(TRACE, "tid={}, native tid={}", thread->tid(), (uintptr_t)syscall(SYS_gettid));
#endif

	if (sigsetjmp(thread->m_return_ctx, 1) == 0)
	{
		if (!thread->m_started)
		{
			pthread_setspecific(thread_obj_key, thread);

			LOG(TRACE, "execute({}): ready to start", thread->tid());
			thread->m_started = true;
			args->start_result = ExecutionThread::THREAD_EXECUTION_RESULT::OK;
			args->barrier.release();
			args = nullptr;

			std::atomic_signal_fence(std::memory_order_seq_cst);
			assert(pthread_getspecific(thread_obj_key) == thread);
			thread->m_sigill_request = 2;
			_trigger_sigill();
			LOG(CRITICAL, "execute({}): _trigger_sigill returned at an expected location", thread->tid());
		}

		// TODO: this might be recoverable, any use-cases?
		throw std::runtime_error("unrecoverable failure: sigsetjmp/pthread_sigqueue");
	}

	asm volatile("" : : : "memory");

	thread_handle_signal();
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
		std::lock_guard guard{m_thread_lock};

		m_state = THREAD_EXECUTION_STATE::RUNNING;
		m_result = THREAD_EXECUTION_RESULT::OK;

		if (pthread_create(&m_thread, NULL, (void *(*)(void *))thread_bootstrap, &args) != 0)
		{
			_execute_recover_until_point(until, m_until_point_instr_backup, m_coord.proxy());
			throw std::runtime_error("pthread_create failed");
		}

		m_thread_is_valid = true;
		m_exitwait.release();
	}

	args.barrier.acquire();
	return args.start_result;
}

ExecutionThread::THREAD_EXECUTION_RESULT ExecutionThread_Native::join(uint32_t *retval)
{
	if (m_state != THREAD_EXECUTION_STATE::UNSTARTED)
	{
		void *thread_retval;
		int err = 0;

		// https://udrepper.livejournal.com/16844.html
		{
			std::lock_guard guard{m_thread_lock};
			if (m_thread_is_valid)
			{
				err = pthread_join(m_thread, &thread_retval);
				m_thread_is_valid = false;
			}
		}

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
	{
		if (m_exitwait.try_acquire())
		{
			// the target thread won't be able to exit
			if (pthread_equal(pthread_self(), m_thread) == 0) // if not equal
			{
				pthread_kill(m_thread, SIGILL);
			}
			m_exitwait.release();
		}
	}
}

uintptr_t NativeEngineARM::mmap(uintptr_t preferred, size_t length)
{
	std::lock_guard g{m_memory_lock};
	auto ptr = m_allocator.alloc(0x1000, length);
	if (ptr)
	{
		m_translator.add(ptr, length, ptr);
	}
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

	std::lock_guard guard{m_threads_lock};
	m_threads.insert(casted);

	return casted;
}

int NativeEngineARM::thread_destroy(std::weak_ptr<ExecutionThread> thread)
{
	if (auto p = thread.lock())
	{
		std::lock_guard guard{m_threads_lock};
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
	do
	{
		size_t left;
		std::shared_ptr<ExecutionThread> p;

		{
			std::lock_guard guard{m_threads_lock};

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

void NativeEngineARM::thread_stopall(int retval)
{
	std::lock_guard guard{m_threads_lock};
	for (auto &thread : m_threads)
		thread->stop();
}

#include <psp2cldr/context.hpp>

void ExecutionThread_Native::panic(int code, LoadContext *load)
{}

void NativeEngineARM::panic(int code, LoadContext *load)
{
	PANIC_LOG("Backend: NativeEngineARM");
	thread_stopall(code);

	std::lock_guard guard{m_threads_lock};
	for (auto &p_thread : m_threads)
	{
		PANIC_LOG("Thread: tid={:#x}", p_thread->tid());
#define reg_info_dump(reg)                                                                                                                                     \
	{                                                                                                                                                          \
		auto _reg_val = (*p_thread)[RegisterAccessProxy::Register::reg]->r();                                                                                  \
		if (load)                                                                                                                                              \
		{                                                                                                                                                      \
			auto _pair = load->try_resolve_location(_reg_val);                                                                                                 \
			if (!_pair.first.empty())                                                                                                                          \
				PANIC_LOG("\t{}={:#010x}\t<{} + {:#010x}>", #reg, _reg_val, _pair.first, _pair.second);                                                        \
			else                                                                                                                                               \
				PANIC_LOG("\t{}={:#010x}\t<\?\?>", #reg, _reg_val);                                                                                            \
		}                                                                                                                                                      \
		else                                                                                                                                                   \
			PANIC_LOG("\t{}={:#010x}", #reg, _reg_val);                                                                                                        \
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
		{}
	}
}

static bool _install_sigaction(int sig, void (*f)(int, siginfo_t *, void *), bool mask_emptyset = false, struct sigaction *old_action = NULL)
{
	struct sigaction action;
	if (mask_emptyset)
		sigemptyset(&action.sa_mask);
	else
		sigfillset(&action.sa_mask);

	action.sa_sigaction = f;
	action.sa_flags = SA_SIGINFO | SA_ONSTACK;
	if (sigaction(sig, &action, old_action) == 0)
	{
		return true;
	}
	LOG(CRITICAL, "sigaction for {} failed with error: {}", sig, strerror(errno));
	return false;
}

static bool _uninstall_sigaction(int sig, struct sigaction *old_action)
{
	if (sigaction(sig, old_action, NULL) == 0)
	{
		return true;
	}
	return false;
}

NativeEngineARM::NativeEngineARM() : ExecutionCoordinator()
{
	assert(g_coord == nullptr);
	g_coord = this;

	m_sigstack = (char *)std::aligned_alloc(16, m_szsigstack);
	if (pthread_key_create(&thread_obj_key, NULL) == 0)
	{
		if (pthread_key_create(&thread_init_key, NULL) == 0)
		{
			stack_t ss;
			ss.ss_size = m_szsigstack;
			ss.ss_flags = 0;
			ss.ss_sp = (void *)m_sigstack;
			if (sigaltstack(&ss, &m_old_ss) == 0)
			{
				LOG(TRACE, "sigaltstack: sigstack={:#010x}", (uintptr_t)m_sigstack);

				if (_install_sigaction(SIGILL, _sig_handler, false, &m_old_action_ill))
				{
					return;
				}
				else
				{
					LOG(CRITICAL, "_install_sigaction failed");
					sigaltstack(&m_old_ss, NULL);
				}
			}
			else
			{
				LOG(CRITICAL, "sigaltstack failed with error: {}", strerror(errno));
			}
		}
		else
		{
			LOG(CRITICAL, "pthread_key_create failed with error: {}", strerror(errno));
		}
	}
	else
	{
		LOG(CRITICAL, "pthread_key_create failed with error: {}", strerror(errno));
	}
	throw std::runtime_error("NativeEngineARM initialization failed");
}

NativeEngineARM::~NativeEngineARM()
{
	_uninstall_sigaction(SIGILL, &m_old_action_ill);
	sigaltstack(&m_old_ss, NULL);
	pthread_key_delete(thread_init_key);
	pthread_key_delete(thread_obj_key);
	free(m_sigstack);
	g_coord = nullptr;
}
