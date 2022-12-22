/*
 * Copyright (C) 2021-2022 Jianye Chen
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

#ifndef OSL_HANDLE_H
#define OSL_HANDLE_H

#include <cstdint>
#include <memory>
#include <mutex>
#include <random>
#include <stdexcept>
#include <unordered_map>
#include <unordered_set>

typedef int32_t OSL_HANDLE;

// MT-safe
class HandleAllocator
{
	static inline std::random_device rand_dev{};
	static inline std::mt19937 generator{HandleAllocator::rand_dev()};
	static inline std::mutex generator_lock;

public:
	// [valid_low, valid_high]
	HandleAllocator(OSL_HANDLE low, OSL_HANDLE high = INT32_MAX) : m_low(low), m_high(high), m_distr(low, high)
	{
		if (m_high < m_low || m_high - m_low < 100)
			throw std::invalid_argument("handler space is too small");
	}

	virtual ~HandleAllocator()
	{}

public:
	virtual bool is_valid(OSL_HANDLE key) const
	{
		std::lock_guard guard{m_lock};
		return m_allocated.count(key);
	}

	virtual OSL_HANDLE alloc()
	{
		std::lock_guard guard{m_lock};

		if (m_allocated.size() > (m_high - m_low) / 4 * 3)
			throw std::runtime_error("out of handle space, use a better implementation ...");

		OSL_HANDLE key;
		do
		{
			{
				std::lock_guard generator_guard{generator_lock};
				key = m_distr(generator);
			}
		} while (m_allocated.count(key) != 0);

		m_allocated.insert(key);
		return key;
	}

	virtual void free(OSL_HANDLE key)
	{
		std::lock_guard guard{m_lock};
		if (m_allocated.erase(key) == 0)
			throw std::invalid_argument("attempted to free a handle that was not allocated");
	}

protected:
	OSL_HANDLE m_low;
	OSL_HANDLE m_high;

	mutable std::recursive_mutex m_lock;
	std::unordered_set<OSL_HANDLE> m_allocated;

	std::uniform_int_distribution<uint32_t> m_distr;
};

// MT-safe
template <class T> class HandleStorage : public HandleAllocator
{
public:
	HandleStorage(OSL_HANDLE low, OSL_HANDLE high = INT32_MAX) : HandleAllocator(low, high)
	{}
	virtual ~HandleStorage()
	{}

public:
	virtual OSL_HANDLE alloc(const T &t)
	{
		std::lock_guard guard{m_lock};
		auto handle = HandleAllocator::alloc();
		m_storage[handle] = t;
		return handle;
	}

	virtual OSL_HANDLE alloc(T &&t)
	{
		std::lock_guard guard{m_lock};
		auto handle = HandleAllocator::alloc();
		m_storage[handle] = std::move(t);
		return handle;
	}

	virtual OSL_HANDLE alloc() override
	{
		std::lock_guard guard{m_lock};
		auto handle = HandleAllocator::alloc();
		m_storage[handle];
		return handle;
	}

	virtual void free(OSL_HANDLE key) override
	{
		std::lock_guard guard{m_lock};
		m_storage.erase(key);
		HandleAllocator::free(key);
	}

public:
	virtual T &operator[](OSL_HANDLE idx)
	{
		std::lock_guard guard{m_lock};
		return m_storage[idx];
	}

	virtual T at(OSL_HANDLE key) const
	{
		std::lock_guard guard{m_lock};
		return m_storage.at(key);
	}

protected:
	std::unordered_map<OSL_HANDLE, T> m_storage;
};

#endif
