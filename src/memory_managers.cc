/*
 * Copyright (C) 2021-2022 Jianye Chen
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

#include <psp2cldr/memory_managers.hpp>

#include <algorithm>
#include <stdexcept>

MemoryScheduler::MemoryScheduler(size_t alignment, const range &memory, const std::vector<range> &occupied_ranges)
    : memory(memory), m_alignment(alignment)
{
    for (auto &o : occupied_ranges)
        m_occupied.push_back(std::make_pair(o, OccupationType::BLOCKED));
    std::sort(m_occupied.begin(), m_occupied.end(),
              [](auto &left, auto &right) { return left.first.first < right.first.first; });
}

uintptr_t MemoryScheduler::mmap(uintptr_t preferred, size_t length)
{
    if (length != align(length))
        throw std::invalid_argument("mmap-ing without an aligned length");

    uintptr_t past = memory.first;
    for (int i = 0; i < m_occupied.size(); i++)
    {
        if (m_occupied[i].first.first - past >= length)
        {
            m_occupied.insert(m_occupied.begin() + i,
                              std::make_pair(std::make_pair(past, past + length), OccupationType::MAPPED));
            return past;
        }
        else
        {
            past = m_occupied[i].first.second;
        }
    }

    if (memory.second - past >= length)
    {
        m_occupied.push_back(std::make_pair(std::make_pair(past, past + length), OccupationType::MAPPED));
        return past;
    }
    else
    {
        return 0;
    }
}

int MemoryScheduler::munmap(uintptr_t addr, size_t length)
{
    return 0;
}

uintptr_t MemoryTranslator::translate(const uintptr_t addr) const
{
    std::lock_guard guard{m_lock};
    auto it = std::upper_bound(m_memory_map.begin(), m_memory_map.end(), addr, [](auto &left, auto &right) {
        return right.first.second > left;
    }); // first range [a, b) that has b > addr

    if (it != m_memory_map.end() && it->first.first <= addr)
        return (addr - it->first.first) + it->second;

    throw std::runtime_error("attempted to translate an unmapped address");
}

#include <psp2cldr/implementation/logger.hpp>
uintptr_t MemoryTranslator::add(uintptr_t addr, size_t length, uintptr_t ptr)
{
    std::lock_guard guard{m_lock};
#ifndef NDEBUG
    for (auto &entry : m_memory_map)
    {
        auto rg = entry.first;
        if (addr >= rg.second || rg.first >= addr + length)
        {
            continue;
        }

        LOG(CRITICAL, "memory collision: {:#010x}-{:#010x} {:#010x}-{:#010x}", rg.first, rg.second, addr,
            addr + length);
        throw std::runtime_error("memory collision detected");
    }
#endif
    m_memory_map[std::make_pair(addr, addr + length)] = ptr;
    return addr;
}

int MemoryTranslator::erase(uintptr_t addr, size_t length)
{
    std::lock_guard guard{m_lock};
    auto it = m_memory_map.find(std::make_pair(addr, addr + length));
    if (it == m_memory_map.end())
        throw std::runtime_error("attempted to erase an unmapped region");

    m_memory_map.erase(it);
    return 0;
}

#ifdef _MSC_VER
#include <malloc.h>
#else
#include <sys/mman.h>
#endif

uintptr_t MemoryAllocator::alloc(size_t alignment, size_t length)
{
#ifdef _MSC_VER
    auto ptr = (uintptr_t)_aligned_malloc(length, alignment);
#else
    // native: some implementations of aligned_malloc does not acquire executable memory
    auto ptr = (uintptr_t)mmap(NULL, length, PROT_EXEC | PROT_READ | PROT_WRITE,
                               MAP_ANONYMOUS | MAP_POPULATE | MAP_PRIVATE, -1, 0);
    if (ptr == -1) // MAP_FAILED
    {
        ptr = 0; // we should always use 0 to indicate failure to align with malloc
        LOG(WARN, "memory allocation faild size={:#010x}, strerror={}", length, strerror(errno));
    }
#endif
    if (ptr)
    {
        m_allocated[ptr] = std::make_pair(alignment, length);
        return ptr;
    }
    return 0;
}

void MemoryAllocator::free(uintptr_t ptr)
{
    auto it = m_allocated.find(ptr);
    if (it == m_allocated.end())
        throw std::runtime_error("freeing an unallocated block");
    auto length = it->second.second;
    m_allocated.erase(it);

#ifdef _MSC_VER
    _aligned_free((void *)ptr);
#else
    if (munmap((void *)ptr, length) == -1)
        throw std::runtime_error(strerror(errno));
#endif
}
