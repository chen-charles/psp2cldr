#include <psp2cldr/memory_managers.hpp>

#include <algorithm>
#include <stdexcept>

MemoryScheduler::MemoryScheduler(size_t alignment, const range &memory, const std::vector<range> &occupied_ranges) : memory(memory), m_alignment(alignment)
{
    for (auto &o : occupied_ranges)
        m_occupied.push_back(std::make_pair(o, OccupationType::BLOCKED));
    std::sort(m_occupied.begin(), m_occupied.end(), [](auto &left, auto &right) {
        return left.first.first < right.first.first;
    });
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
            m_occupied.insert(m_occupied.begin() + i, std::make_pair(std::make_pair(past, past + length), OccupationType::MAPPED));
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
    auto it = std::upper_bound(m_memory_map.begin(), m_memory_map.end(), addr, [](auto &left, auto &right) {
        return right.first.second > left;
    }); // first range [a, b) that has b > addr

    if (it != m_memory_map.end() && it->first.first <= addr)
        return (addr - it->first.first) + it->second;

    throw std::runtime_error("attempted to translate an unmapped address");
}

uintptr_t MemoryTranslator::add(uintptr_t addr, size_t length, uintptr_t ptr)
{
    // TODO: collision checks
    m_memory_map[std::make_pair(addr, addr + length)] = ptr;
    return addr;
}

int MemoryTranslator::erase(uintptr_t addr, size_t length)
{
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
    auto ptr = (uintptr_t)mmap(NULL, length, PROT_EXEC | PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_POPULATE | MAP_PRIVATE, -1, 0);
#endif
    m_allocated[ptr] = std::make_pair(alignment, length);
    return ptr;
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
    munmap((void *)ptr, length);
#endif
}
