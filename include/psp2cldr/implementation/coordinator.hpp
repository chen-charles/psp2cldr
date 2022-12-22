/*
 * Copyright (C) 2021-2022 Jianye Chen
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

#ifndef PSP2CLDR_EXECCOORD_IMPL_H
#define PSP2CLDR_EXECCOORD_IMPL_H

#include <type_traits>

#include <psp2cldr/coordinator.hpp>

#if PSP2CLDR_NATIVE
#include <psp2cldr/implementation/native.hpp>
#elif PSP2CLDR_NATIVE_MSVC
#include <psp2cldr/implementation/native_msvc.hpp>
#elif PSP2CLDR_EMULATION
#include <psp2cldr/implementation/emulation.hpp>
#else
#error Either PSP2CLDR_NATIVE, PSP2CLDR_NATIVE_MSVC or PSP2CLDR_EMULATION must be defined.
#endif

#ifndef Coordinator_Impl
#error Coordinator Implementation must define Coordinator_Impl
#endif

static_assert(std::is_convertible<Coordinator_Impl *, ExecutionCoordinator *>::value, "Coordinator_Impl must be derived from ExecutionCoordinator");

#endif
