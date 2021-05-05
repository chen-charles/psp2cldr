#ifndef PSP2CLDR_EXECCOORD_IMPL_H
#define PSP2CLDR_EXECCOORD_IMPL_H

#include <type_traits>

#include <psp2cldr/coordinator.hpp>

#if PSP2CLDR_NATIVE
#include <psp2cldr/native.hpp>
#elif PSP2CLDR_EMULATION
#include <psp2cldr/emulation.hpp>
#else
#error Either PSP2CLDR_NATIVE or PSP2CLDR_EMULATION must be defined.
#endif

#ifndef Coordinator_Impl
#error Coordinator Implementation must define Coordinator_Impl
#endif

static_assert(std::is_convertible<Coordinator_Impl *, ExecutionCoordinator *>::value, "Coordinator_Impl must be derived from ExecutionCoordinator");

#endif
