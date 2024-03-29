/*
 * Copyright (C) 2021-2022 Jianye Chen
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

#ifndef PSP2CLDR_ARCH_H
#define PSP2CLDR_ARCH_H

#include <elf.h> // gcc

#ifndef NID_t
#define NID_t uint32_t
#endif

#ifndef NIDHASH_t
#define NIDHASH_t uint64_t
#endif

static inline NIDHASH_t nid_hash(NID_t libraryNID, NID_t functionNID)
{
	return ((NIDHASH_t)libraryNID << 32) | functionNID;
}

#define STRINGIZE_IMPL(x) #x
#define STRINGIZE(x) STRINGIZE_IMPL(x)

/* we will always send posix signal codes to the interrupt handlers (P1990) */
#define POSIX_SIGINT 2
#define POSIX_SIGILL 4
#define POSIX_SIGTRAP 5
#define POSIX_SIGABRT 6
#define POSIX_SIGSEGV 11

/*
Bitwise immediate operations (not changing the given var)
*/
#define SETBIT(var, pos) ((var) | ((uintptr_t)1 << (pos)))
#define CLEARBIT(var, pos) ((var) & ~((uintptr_t)1 << (pos)))
#define FLIPBIT(var, pos) ((var) ^ ((uintptr_t)1 << (pos)))
#define TESTBIT(var, pos) ((var) & ((uintptr_t)1 << (pos)))

/*
Bitwise immediate value
*/
#define IMMEDIATE_SETBIT(pos) (1 << pos)

/*
Bitwise modifications
*/
#define setbit(pVal, pos) (*(pVal) |= ((uintptr_t)1 << (pos)))
#define clearbit(pVal, pos) (*(pVal) &= ~((uintptr_t)1 << (pos)))
#define flipbit(pVal, pos) (*(pVal) ^= ((uintptr_t)1 << (pos)))
#define testbit(pVal, pos) (*(pVal) & ((uintptr_t)1 << (pos)))

#endif
