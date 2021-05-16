#ifndef PSP2CLDR_MEMMGR_H
#define PSP2CLDR_MEMMGR_H

#include <psp2cldr/arch.h>

#include <map>
#include <memory>
#include <mutex>
#include <unordered_map>
#include <vector>

static inline uint32_t align_up(const uint32_t value, const uint32_t alignment) { return (value + alignment - 1) - (value + alignment - 1) % alignment; }

class MemoryScheduler
{
public:
    using range = std::pair<uintptr_t, uintptr_t>;
    MemoryScheduler(size_t alignment, const range &memory, const std::vector<range> &occupied_ranges = {});
    virtual ~MemoryScheduler() {}

    static inline bool in_range(uintptr_t v, range &r) { return v >= r.first && v < r.second; }

public:
    size_t align(const size_t length) const { return align_up(length, alignment()); }
    size_t alignment() const { return m_alignment; }

    virtual uintptr_t mmap(uintptr_t preferred, size_t length);
    virtual int munmap(uintptr_t addr, size_t length);

protected:
    const range memory;
    enum class OccupationType
    {
        BLOCKED,
        MAPPED,
    };

    std::vector<std::pair<range, OccupationType>> m_occupied; // sorted
    size_t m_alignment;
};

// MT-safe
class MemoryTranslator
{
public:
    MemoryTranslator() {}
    virtual ~MemoryTranslator() { m_memory_map.clear(); }

public:
    using range = std::pair<uintptr_t, uintptr_t>;

    uintptr_t translate(const uintptr_t addr) const;

    virtual uintptr_t add(uintptr_t addr, size_t length, uintptr_t ptr); // returns addr
    virtual int erase(uintptr_t addr, size_t length);

    const std::map<range, uintptr_t> memory_map() const
    {
        std::lock_guard guard{m_lock};
        return m_memory_map;
    };

protected:
    // ramge [a, b) -> translated base
    mutable std::mutex m_lock;
    std::map<range, uintptr_t> m_memory_map;
};

class MemoryAllocator
{
public:
    MemoryAllocator() {}
    virtual ~MemoryAllocator() {}

public:
    virtual uintptr_t alloc(size_t alignment, size_t length);
    virtual void free(uintptr_t ptr);

protected:
    std::unordered_map<uintptr_t, std::pair<size_t, size_t>> m_allocated;
};

#endif