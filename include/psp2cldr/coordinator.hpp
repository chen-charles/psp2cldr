/*
 * Copyright (C) 2021-2022 Jianye Chen
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

#ifndef PSP2CLDR_EXECCOORD_H
#define PSP2CLDR_EXECCOORD_H

#include <atomic>
#include <cstdint>
#include <exception>
#include <functional>
#include <memory>
#include <mutex>
#include <unordered_map>
#include <unordered_set>

#include <psp2cldr/access_proxy.hpp>

class InterruptContext;
class LoadContext;

class ExecutionCoordinator;

class TLSKey
{
public:
	TLSKey()
	{}
	~TLSKey()
	{
		mapping.clear();
	}

	std::mutex lock;
	std::unordered_map<uint32_t, uintptr_t> mapping; // threadID, value
};

class TLS
{
	static inline std::unordered_set<TLSKey *> tls;
	static inline std::recursive_mutex tls_mutex;

public:
	TLS(uint32_t threadID) : m_id(threadID)
	{}

	~TLS()
	{
		std::lock_guard guard{tls_mutex};
		for (auto &key : tls)
		{
			std::lock_guard g{key->lock};
			key->mapping.erase(m_id);
		}
	}

	static void reset()
	{
		std::lock_guard guard{tls_mutex};
		for (auto &key : tls)
		{
			delete key;
		}
		tls.clear();
	}

	uintptr_t alloc()
	{
		std::lock_guard guard{tls_mutex};
		auto key = new TLSKey();
		tls.insert(key);
		return (uintptr_t)key;
	}

	void set(uintptr_t key, uintptr_t value)
	{
		std::lock_guard guard{tls_mutex};
		TLSKey *entry = (TLSKey *)key;
		if (tls.count(entry))
		{
			std::lock_guard g{entry->lock};
			entry->mapping[m_id] = value;
		}
		else
			throw std::out_of_range("invalid key");
	}

	uintptr_t get(uintptr_t key) const
	{
		std::lock_guard guard{tls_mutex};
		TLSKey *entry = (TLSKey *)key;
		if (tls.count(entry))
		{
			std::lock_guard g{entry->lock};
			return entry->mapping[m_id];
		}
		else
			throw std::out_of_range("invalid key");
	}

	void free(uintptr_t key)
	{
		std::lock_guard guard{tls_mutex};
		TLSKey *entry = (TLSKey *)key;
		if (tls.erase(entry))
			delete entry;
		else
			throw std::out_of_range("invalid key");
	}

protected:
	uint32_t m_id;
};

class ExecutionThread
{
private:
	static inline std::atomic<uint32_t> _id_ctr = 1;
	mutable uint32_t m_tid = 0;

public:
	uint32_t tid() const
	{
		if (m_tid == 0)
			return m_tid = _id_ctr++;
		return m_tid;
	}

public:
	ExecutionThread() : tls(tid())
	{}
	virtual ~ExecutionThread()
	{}

public:
	enum class THREAD_EXECUTION_STATE : uint32_t
	{
		UNSTARTED,
		RUNNING,
		RESTARTABLE,
		EXITED // died, will never leave this state
	};
	// thread is not accessible when it's running
	// we can attempt to wait for the thread to become inspect-able

	enum class THREAD_EXECUTION_RESULT : uint32_t
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

	virtual void panic(int code = 0, LoadContext *load = nullptr) = 0;

	virtual void register_interrupt_callback(std::function<void(ExecutionCoordinator &, ExecutionThread &, uint32_t)> callback) = 0;

	virtual bool is_thumb() const
	{
		return (*this)[RegisterAccessProxy::Register::CPSR]->r() & (1 << 5);
	}

public:
	TLS tls;

public:
	// register access
	virtual std::shared_ptr<RegisterAccessProxy> operator[](RegisterAccessProxy::Register name) = 0;
	virtual std::shared_ptr<const RegisterAccessProxy> operator[](RegisterAccessProxy::Register name) const = 0;
};

class ExecutionCoordinator
{
public:
	ExecutionCoordinator()
	{}
	virtual ~ExecutionCoordinator()
	{}

public:
	virtual MemoryAccessProxy &proxy() const = 0;
	virtual uintptr_t mmap(uintptr_t preferred, size_t length) = 0; // always RWX
	virtual int munmap(uintptr_t addr, size_t length) = 0;

	/**
	 * Threading Support
	 * on platforms that does not natively support target threading, only a single thread of execution on the target
	 * will be active at any given time.
	 */
	[[nodiscard]] virtual std::shared_ptr<ExecutionThread> thread_create() = 0;
	virtual int thread_destroy(std::weak_ptr<ExecutionThread> thread) = 0;
	virtual void thread_joinall() = 0;
	virtual void thread_stopall(int retval = 0) = 0;

	virtual void panic(int code = 0, LoadContext *load = nullptr) = 0;
	virtual void panic(ExecutionThread *thread = nullptr, LoadContext *load = nullptr, int code = 0,
					   const char *msg = nullptr); // forward to panic impl.

	// default interrupt callback for all newly created threads
	virtual void register_interrupt_callback(std::function<void(ExecutionCoordinator &, ExecutionThread &, uint32_t)> callback) = 0;
};

// when running natively, exec state control is ~equivalent to a gdb client

#endif
