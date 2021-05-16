#include <algorithm>
#include <cassert>

#include <psp2cldr/emulation.hpp>
#include <psp2cldr/logger.hpp>

static void assert_uc_err(uc_err err, const char *message)
{
    if (err != UC_ERR_OK)
        throw std::runtime_error(message);
}

uint64_t EmulationAccessProxy::copy_in(uint64_t dest, const void *src, size_t num) const
{
    void *real_dest = (void *)m_translator.translate(dest);
    memmove(real_dest, src, num);
    return dest;
}

void *EmulationAccessProxy::copy_out(void *dest, uint64_t src, size_t num) const
{
    void *real_src = (void *)m_translator.translate(src);
    memmove(dest, real_src, num);
    return dest;
}

uint32_t RegisterAccessProxy_Unicorn::w(uint32_t value)
{
    auto err = uc_reg_write(m_engine, uc_mapping.at(name()), &value);
    assert_uc_err(err, "unicorn register write failed");
    return value;
}

uint32_t RegisterAccessProxy_Unicorn::r() const
{
    uint32_t out;
    auto err = uc_reg_read(m_engine, uc_mapping.at(name()), &out);
    assert_uc_err(err, "unicorn register read failed");
    return out;
}

ExecutionThread_Unicorn::ExecutionThread_Unicorn(ExecutionCoordinator &coord) : ExecutionThread(), m_coord(coord)
{
    auto err_msg = "emulation engine initialization failed";
    uc_err err;
    err = uc_open(UC_ARCH_ARM, UC_MODE_ARM, &m_engine);
    assert_uc_err(err, err_msg);

    /* VFP */
    uint32_t cpacr;
    err = uc_reg_read(m_engine, UC_ARM_REG_C1_C0_2, &cpacr);
    assert_uc_err(err, err_msg);

    cpacr |= 0xf << 20; // CP10 and CP11: allow user-mode access: https://developer.arm.com/documentation/ddi0388/i/system-control/register-descriptions/coprocessor-access-control-register
    err = uc_reg_write(m_engine, UC_ARM_REG_C1_C0_2, &cpacr);
    assert_uc_err(err, err_msg);

    uint32_t fpexc = 1 << 30; // https://developer.arm.com/documentation/dui0473/c/neon-and-vfp-programming/fpexc--the-floating-point-exception-register
    err = uc_reg_write(m_engine, UC_ARM_REG_FPEXC, &fpexc);
    assert_uc_err(err, err_msg);

    /* hooks */
    err = uc_hook_add(m_engine, &m_hook_insn_invalid, UC_HOOK_INSN_INVALID, (void *)&_uc_insn_invalid_handler, this, 1, 0);
    assert_uc_err(err, err_msg);

    err = uc_hook_add(m_engine, &m_hook_mem_invalid, UC_HOOK_MEM_INVALID, (void *)&_uc_invalid_mem_handler, this, 1, 0);
    assert_uc_err(err, err_msg);
}

ExecutionThread_Unicorn::~ExecutionThread_Unicorn()
{
    stop(0);
    if (m_thread.joinable())
        m_thread.join();

    uc_hook_del(m_engine, m_hook_insn_invalid);
    uc_hook_del(m_engine, m_hook_mem_invalid);
    uc_close(m_engine);
}

uintptr_t UnicornEngineARM::mmap(uintptr_t preferred, size_t length)
{
    std::lock_guard g{m_memory_lock};
    auto aligned_length = m_scheduler.align(length);
    auto addr = m_scheduler.mmap(preferred, aligned_length);
    if (addr)
    {
        auto ptr = m_allocator.alloc(m_scheduler.alignment(), aligned_length);
        m_translator.add(addr, aligned_length, ptr);

        std::lock_guard<std::recursive_mutex> guard(m_threads_lock);
        for (auto &thread : m_threads)
        {
            auto casted = std::dynamic_pointer_cast<ExecutionThread_Unicorn>(thread);
            auto err = casted->map_ptr(addr, aligned_length, (void *)ptr);
            assert_uc_err(err, "unicorn returned failure for mmap");
        }
    }
    return addr;
}

int UnicornEngineARM::munmap(uintptr_t addr, size_t length)
{
    std::lock_guard g{m_memory_lock};
    auto aligned_length = m_scheduler.align(length);
    auto ptr = m_translator.translate(addr);

    m_translator.erase(addr, aligned_length);
    m_scheduler.munmap(addr, aligned_length);
    m_allocator.free(ptr);

    std::lock_guard<std::recursive_mutex> guard(m_threads_lock);
    for (auto &thread : m_threads)
    {
        auto casted = std::dynamic_pointer_cast<ExecutionThread_Unicorn>(thread);
        auto err = casted->unmap_ptr(addr, aligned_length);
        assert_uc_err(err, "unicorn returned failure for mmap");
    }
    return 0;
}

ExecutionThread::THREAD_EXECUTION_RESULT ExecutionThread_Unicorn::start(uint32_t from, uint32_t until)
{
    switch (m_state)
    {
    case THREAD_EXECUTION_STATE::UNSTARTED:
    case THREAD_EXECUTION_STATE::RESTARTABLE:
        break;
    default:
        return ExecutionThread::THREAD_EXECUTION_RESULT::START_FAILED;
    }

    if (m_thread.joinable())
        m_thread.join();

    if (from & 1) // thumb
        (*this)[RegisterAccessProxy::Register::CPSR]->w((*this)[RegisterAccessProxy::Register::CPSR]->r() | (1 << 5));
    else
        (*this)[RegisterAccessProxy::Register::CPSR]->w((*this)[RegisterAccessProxy::Register::CPSR]->r() & (~(1 << 5)));

    m_state = THREAD_EXECUTION_STATE::RUNNING;

    m_thread = std::thread(
        [=]()
        {
            auto err = uc_emu_start(m_engine, from, until, 0, 0);
            {
                if (m_stop_called)
                {
                    // unsafe to restart?
                    m_state = THREAD_EXECUTION_STATE::EXITED;
                    m_result = THREAD_EXECUTION_RESULT::STOP_CALLED;
                }
                else if (err == UC_ERR_OK)
                {
                    m_state = THREAD_EXECUTION_STATE::RESTARTABLE;
                    m_result = THREAD_EXECUTION_RESULT::STOP_UNTIL_POINT_HIT;
                }
                else
                {
                    m_state = THREAD_EXECUTION_STATE::EXITED;
                    m_result = THREAD_EXECUTION_RESULT::STOP_ERRORED;
                }
            }
        });

    return ExecutionThread::THREAD_EXECUTION_RESULT::OK;
}

ExecutionThread::THREAD_EXECUTION_RESULT ExecutionThread_Unicorn::join(uint32_t *retval)
{
    {
        switch (m_state)
        {
        case THREAD_EXECUTION_STATE::UNSTARTED:
            return ExecutionThread::THREAD_EXECUTION_RESULT::JOIN_FAILED;
        case THREAD_EXECUTION_STATE::RESTARTABLE:
            if (retval != nullptr)
                *retval = (*this)[RegisterAccessProxy::Register::R0]->r();
            return m_result;
        }
    }

    std::lock_guard guard{join_lock};

    if (m_thread.joinable())
    {
        m_thread.join();
        {
            if (m_result == THREAD_EXECUTION_RESULT::STOP_UNTIL_POINT_HIT && retval != nullptr)
                *retval = (*this)[RegisterAccessProxy::Register::R0]->r();

            return m_result;
        }
    }

    return ExecutionThread::THREAD_EXECUTION_RESULT::JOIN_FAILED;
}

void ExecutionThread_Unicorn::stop(uint32_t retval)
{
    m_stop_called = true;
    uc_emu_stop(m_engine);
}

[[nodiscard]] std::shared_ptr<ExecutionThread> UnicornEngineARM::thread_create()
{
    auto thread = std::make_shared<ExecutionThread_Unicorn>(*this);
    for (auto &entry : m_translator.memory_map())
    {
        auto range = entry.first;
        auto ptr = entry.second;

        auto err = thread->map_ptr(range.first, range.second - range.first, (void *)ptr);
        assert_uc_err(err, "unicorn returned failure for mmap");
    }
    thread->register_interrupt_callback(m_intr_callback);
    auto casted = std::dynamic_pointer_cast<ExecutionThread>(thread);

    std::lock_guard<std::recursive_mutex> guard(m_threads_lock);
    m_threads.insert(casted);
    return casted;
}

int UnicornEngineARM::thread_destroy(std::weak_ptr<ExecutionThread> thread)
{
    if (auto p = thread.lock())
    {
        std::lock_guard<std::recursive_mutex> guard(m_threads_lock);
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

void UnicornEngineARM::thread_joinall()
{
    do
    {
        size_t left;
        std::shared_ptr<ExecutionThread> p;

        {
            std::lock_guard<std::recursive_mutex> guard(m_threads_lock);
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

void UnicornEngineARM::thread_stopall(int retval)
{
    std::lock_guard<std::recursive_mutex> guard(m_threads_lock);
    for (auto &thread : m_threads)
        thread->stop();
}

UnicornEngineARM::UnicornEngineARM() : ExecutionCoordinator() {}

UnicornEngineARM::~UnicornEngineARM()
{
    m_threads.clear();
}

#include <psp2cldr/context.hpp>

void ExecutionThread_Unicorn::panic(int code, LoadContext *load)
{
}

void UnicornEngineARM::panic(int code, LoadContext *load)
{
    PANIC_LOG("Backend: UnicornEngineARM");
    std::lock_guard<std::recursive_mutex> guard(m_threads_lock);
    for (auto &p_thread : m_threads)
    {
        PANIC_LOG("Thread: tid={:#x}", p_thread->tid());
#define reg_info_dump(reg)                                                                              \
    {                                                                                                   \
        auto _reg_val = (*p_thread)[RegisterAccessProxy::Register::reg]->r();                           \
        if (load)                                                                                       \
        {                                                                                               \
            auto _pair = load->try_resolve_location(_reg_val);                                          \
            if (!_pair.first.empty())                                                                   \
                PANIC_LOG("\t{}={:#010x}\t<{} + {:#010x}>", #reg, _reg_val, _pair.first, _pair.second); \
            else                                                                                        \
                PANIC_LOG("\t{}={:#010x}\t<\?\?>", #reg, _reg_val);                                     \
        }                                                                                               \
        else                                                                                            \
            PANIC_LOG("\t{}={:#010x}", #reg, _reg_val);                                                 \
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
        {
        }
    }
}
