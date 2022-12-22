/*
 * Copyright (C) 2021-2022 Jianye Chen
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

#ifndef PSP2CLDR_ACCPROXY_H
#define PSP2CLDR_ACCPROXY_H

#include <cstring>
#include <stdexcept>
#include <type_traits>

#include <psp2cldr/arch.h>

class MemoryAccessProxy
{
public:
	virtual ~MemoryAccessProxy()
	{
	}

public:
    // Copy Into the Target Environment from the Host
    virtual uint64_t copy_in(uint64_t dest, const void *src, size_t num) const = 0;

    // Copy Out from the Target Environment to the Host
    virtual void *copy_out(void *dest, uint64_t src, size_t num) const = 0;

public:
	template <class T, typename = std::enable_if_t<std::is_arithmetic<T>::value>> T r(uint64_t location) const
	{
		T out;
		copy_out(&out, location, sizeof(T));
		return out;
	}

	template <class T, typename = std::enable_if_t<std::is_arithmetic<T>::value>> void w(uint64_t location, const T &value) const
	{
		copy_in(location, &value, sizeof(T));
	}
};

struct Float128
{
	uint64_t low;
	uint64_t high;
};
static_assert(sizeof(struct Float128) == sizeof(uint64_t) * 2);

/**
 * RegisterAccessProxy
 *
 * $PC
 * R: should always return LSB-clear value
 * W: should automatically set CPSR.T if LSB-set
 */
class RegisterAccessProxy
{
public:
	enum class Register : uint8_t
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

		FPSCR,

#pragma region SIMD
		// Advanced SIMD and Floating-point register mapping, see DDI0406C A.2.6.2.3
		Q0,
		Q1,
		Q2,
		Q3,
		Q4,
		Q5,
		Q6,
		Q7,
		Q8,
		Q9,
		Q10,
		Q11,
		Q12,
		Q13,
		Q14,
		Q15,
		D0,
		D1,
		D2,
		D3,
		D4,
		D5,
		D6,
		D7,
		D8,
		D9,
		D10,
		D11,
		D12,
		D13,
		D14,
		D15,
		D16,
		D17,
		D18,
		D19,
		D20,
		D21,
		D22,
		D23,
		D24,
		D25,
		D26,
		D27,
		D28,
		D29,
		D30,
		D31,
		S0,
		S1,
		S2,
		S3,
		S4,
		S5,
		S6,
		S7,
		S8,
		S9,
		S10,
		S11,
		S12,
		S13,
		S14,
		S15,
		S16,
		S17,
		S18,
		S19,
		S20,
		S21,
		S22,
		S23,
		S24,
		S25,
		S26,
		S27,
		S28,
		S29,
		S30,
		S31,
#pragma endregion SIMD
	};

	RegisterAccessProxy(Register name) : m_name(name)
	{
		if (name == Register::INVALID)
		{
            throw std::logic_error("accessing an invalid register");
		}
	}

	virtual ~RegisterAccessProxy()
	{
	}

	virtual uint32_t w(uint32_t value) = 0;
	virtual uint32_t r() const = 0;

#pragma region SIMD
	// Advanced SIMD and Floating-point register mapping, see DDI0406C A.2.6.2.3

	virtual Float128 w_Q(Float128 value) = 0;
	virtual Float128 r_Q() const = 0;

	virtual uint64_t w_D(uint64_t value) = 0;
	virtual uint64_t r_D() const = 0;

	virtual uint32_t w_S(uint32_t value) = 0;
	virtual uint32_t r_S() const = 0;

#pragma endregion SIMD

	Register name() const
	{
		return m_name;
	}

private:
    Register m_name;
};

#endif
