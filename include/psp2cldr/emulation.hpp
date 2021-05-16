#ifndef PSP2CLDR_EMUENG_H
#define PSP2CLDR_EMUENG_H

#include <atomic>
#include <cstdint>
#include <mutex>
#include <thread>
#include <unordered_set>

#include <unicorn/unicorn.h>
#include <unordered_map>

#include <psp2cldr/access_proxy.hpp>
#include <psp2cldr/arch.h>
#include <psp2cldr/coordinator.hpp>
#include <psp2cldr/memory_managers.hpp>

/* qemu/target/arm/cpu.h */
#define QEMU_ARM_EXCP_UDEF 1
#define QEMU_ARM_EXCP_BKPT 7

class EmulationAccessProxy : public MemoryAccessProxy
{
public:
    EmulationAccessProxy(const MemoryTranslator &translator) : m_translator(translator) {}
    virtual ~EmulationAccessProxy() {}
    virtual uint64_t copy_in(uint64_t dest, const void *src, size_t num) const;
    virtual void *copy_out(void *dest, uint64_t src, size_t num) const;

private:
    const MemoryTranslator &m_translator;
};

class RegisterAccessProxy_Unicorn : public RegisterAccessProxy
{
public:
    RegisterAccessProxy_Unicorn(Register name, uc_engine *engine) : RegisterAccessProxy(name), m_engine(engine) {}
    virtual ~RegisterAccessProxy_Unicorn() {}

    static inline const std::unordered_map<Register, uc_arm_reg> uc_mapping{
#define _create_uc_mapping_item(reg) {Register::reg, UC_ARM_REG_##reg}
        _create_uc_mapping_item(R0),
        _create_uc_mapping_item(R1),
        _create_uc_mapping_item(R2),
        _create_uc_mapping_item(R3),
        _create_uc_mapping_item(R4),
        _create_uc_mapping_item(R5),
        _create_uc_mapping_item(R6),
        _create_uc_mapping_item(R7),
        _create_uc_mapping_item(R8),
        _create_uc_mapping_item(R9),
        _create_uc_mapping_item(R10),
        _create_uc_mapping_item(R11),
        _create_uc_mapping_item(R12),
        _create_uc_mapping_item(R13),
        _create_uc_mapping_item(R14),
        _create_uc_mapping_item(R15),
        _create_uc_mapping_item(CPSR),
    };

    virtual uint32_t w(uint32_t value);

    virtual uint32_t r() const;

protected:
    uc_engine *m_engine;
};

class ExecutionThread_Unicorn : public ExecutionThread
{
public:
    // UC_HOOK_INTR: uc_cb_hookintr_t
    // static void _uc_intr_handler(uc_engine *uc, uint32_t intno, void *user_data)
    // {
    //     auto engine = reinterpret_cast<UnicornEngineARM *>(user_data);
    // }

    // UC_MEM_*_INVALID and UC_MEM_*PROT: uc_cb_eventmem_t
    static void _uc_invalid_mem_handler(uc_engine *uc, uc_mem_type type, uint64_t address, int size, int64_t value, void *user_data)
    {
        auto engine = reinterpret_cast<ExecutionThread_Unicorn *>(user_data);
        engine->m_intr_callback(engine->m_coord, *engine, POSIX_SIGSEGV);
    }

    // UC_HOOK_INSN_INVALID: uc_cb_hookinsn_invalid_t
    static bool _uc_insn_invalid_handler(uc_engine *uc, void *user_data)
    {
        auto engine = reinterpret_cast<ExecutionThread_Unicorn *>(user_data);
        engine->m_intr_callback(engine->m_coord, *engine, POSIX_SIGILL);
        return true;
    }

    ExecutionThread_Unicorn(ExecutionCoordinator &coordinator);
    virtual ~ExecutionThread_Unicorn();

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
        return std::make_shared<RegisterAccessProxy_Unicorn>(name, m_engine);
    }

    virtual std::shared_ptr<const RegisterAccessProxy> operator[](RegisterAccessProxy::Register name) const
    {
        return std::make_shared<const RegisterAccessProxy_Unicorn>(name, m_engine);
    }

public:
    uc_err map_ptr(uint64_t address, size_t size, void *ptr)
    {
        return uc_mem_map_ptr(m_engine, address, size, UC_PROT_READ | UC_PROT_WRITE | UC_PROT_EXEC, ptr);
    }

    uc_err unmap_ptr(uint64_t address, size_t size)
    {
        return uc_mem_unmap(m_engine, address, size);
    }

protected:
    uc_engine *m_engine;
    ExecutionCoordinator &m_coord;

    std::function<void(ExecutionCoordinator &, ExecutionThread &, uint32_t)> m_intr_callback = {};
    uc_hook m_hook_insn_invalid;
    uc_hook m_hook_mem_invalid;

    std::atomic<THREAD_EXECUTION_STATE> m_state{THREAD_EXECUTION_STATE::UNSTARTED};
    THREAD_EXECUTION_RESULT m_result;
    std::atomic<bool> m_stop_called = false;

    std::thread m_thread;
    std::mutex join_lock;
};

class UnicornEngineARM : public ExecutionCoordinator
{
public:
    UnicornEngineARM();
    virtual ~UnicornEngineARM();

    virtual void register_interrupt_callback(std::function<void(ExecutionCoordinator &, ExecutionThread &, uint32_t)> callback)
    {
        m_intr_callback = callback;
    }

    virtual MemoryAccessProxy &proxy() const
    {
        static EmulationAccessProxy static_proxy(m_translator);
        return static_proxy;
    }

    virtual uintptr_t mmap(uintptr_t preferred, size_t length);
    virtual int munmap(uintptr_t addr, size_t length);

    [[nodiscard]] virtual std::shared_ptr<ExecutionThread> thread_create();
    virtual int thread_destroy(std::weak_ptr<ExecutionThread> thread);
    virtual void thread_joinall();
    virtual void thread_stopall(int retval = 0);

    virtual void panic(int code = 0, LoadContext *load = nullptr);

protected:
    MemoryScheduler m_scheduler{0x1000, std::make_pair(0x400000, 0x20000000)};
    MemoryTranslator m_translator;
    MemoryAllocator m_allocator;
    std::recursive_mutex m_memory_lock;

protected:
    std::function<void(ExecutionCoordinator &, ExecutionThread &, uint32_t)> m_intr_callback = {};

protected:
    std::recursive_mutex m_threads_lock;
    std::unordered_set<std::shared_ptr<ExecutionThread>> m_threads;
};

#define Coordinator_Impl UnicornEngineARM

#endif
