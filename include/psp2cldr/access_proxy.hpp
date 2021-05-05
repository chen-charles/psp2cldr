#ifndef PSP2CLDR_ACCPROXY_H
#define PSP2CLDR_ACCPROXY_H

#include <cstring>
#include <stdexcept>
#include <type_traits>

#include <psp2cldr/arch.h>

class MemoryAccessProxy
{
public:
    virtual ~MemoryAccessProxy() {}

public:
    // Copy Into the Target Environment from the Host
    virtual uint64_t copy_in(uint64_t dest, const void *src, size_t num) const = 0;

    // Copy Out from the Target Environment to the Host
    virtual void *copy_out(void *dest, uint64_t src, size_t num) const = 0;

public:
    template <class T, typename = std::enable_if_t<std::is_arithmetic<T>::value>>
    T r(uint64_t location) const
    {
        T out;
        copy_out(&out, location, sizeof(T));
        return out;
    }

    template <class T, typename = std::enable_if_t<std::is_arithmetic<T>::value>>
    void w(uint64_t location, const T &value) const
    {
        copy_in(location, &value, sizeof(T));
    }
};

class RegisterAccessProxy
{
public:
    enum class Register
    {
        INVALID,
        R0,
        R1,
        R2,
        R3,
        R4,
        R5,
        R6,
        R7,
        R8,
        R9,
        R10,
        R11, // FP
        R12, // IP
        R13, // SP
        R14, // LR
        R15, // PC
        CPSR,

        FP = R11,
        IP = R12,
        SP = R13,
        LR = R14,
        PC = R15,
    };

    RegisterAccessProxy(Register name) : m_name(name)
    {
        if (name == Register::INVALID)
        {
            throw std::logic_error("accessing an invalid register");
        }
    }
    virtual ~RegisterAccessProxy() {}

    virtual uint32_t w(uint32_t value) = 0;
    virtual uint32_t r() const = 0;

    Register name() const { return m_name; }

private:
    Register m_name;
};

#endif
