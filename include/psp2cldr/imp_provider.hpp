#ifndef PSP2CLDR_IMP_PROVIDER_INCL_H
#define PSP2CLDR_IMP_PROVIDER_INCL_H

#pragma warning( disable : 4190 )

#include <psp2cldr/access_proxy.hpp>
#include <psp2cldr/arch.h>
#include <psp2cldr/context.hpp>
#include <psp2cldr/coordinator.hpp>
#include <psp2cldr/provider_poke.hpp>

/* intended for libraries providing NID function definitions */

#ifdef _WIN32
#define VITA_EXPORT extern "C" __declspec(dllexport)
#define VITA_EXPORT_CONVENTION __cdecl
#else
#define VITA_EXPORT extern "C" __attribute__((visibility("default")))
#define VITA_EXPORT_CONVENTION
#endif
#define VITA_IMP_NID_EXPORT_NAME(left, right) psp2cldr_imp_##left##_##right##_
#define VITA_IMP_SYM_EXPORT_NAME(name) psp2cldr_imp_##name##_
#define VITA_IMP_RETURN_TYPE std::shared_ptr<HandlerResult>

#define DECLARE_VITA_IMP_NID_EXPORT(libraryNID, functionNID, _alias)                                                               \
    VITA_EXPORT VITA_IMP_RETURN_TYPE VITA_EXPORT_CONVENTION VITA_IMP_NID_EXPORT_NAME(libraryNID, functionNID)(InterruptContext *); \
    static inline VITA_IMP_RETURN_TYPE VITA_EXPORT_CONVENTION _alias(InterruptContext *ctx) { return VITA_IMP_NID_EXPORT_NAME(libraryNID, functionNID)(ctx); }
#define DEFINE_VITA_IMP_NID_EXPORT(libraryNID, functionNID) VITA_EXPORT VITA_IMP_RETURN_TYPE VITA_EXPORT_CONVENTION VITA_IMP_NID_EXPORT_NAME(libraryNID, functionNID)(InterruptContext * ctx)

#define DECLARE_VITA_IMP_SYM_EXPORT(name) \
    VITA_EXPORT VITA_IMP_RETURN_TYPE VITA_EXPORT_CONVENTION VITA_IMP_SYM_EXPORT_NAME(name)(InterruptContext *);
#define DEFINE_VITA_IMP_SYM_EXPORT(name) VITA_EXPORT VITA_IMP_RETURN_TYPE VITA_EXPORT_CONVENTION VITA_IMP_SYM_EXPORT_NAME(name)(InterruptContext * ctx)

#define PARAM_0 ctx->thread[RegisterAccessProxy::Register::R0]->r()
#define PARAM_1 ctx->thread[RegisterAccessProxy::Register::R1]->r()
#define PARAM_2 ctx->thread[RegisterAccessProxy::Register::R2]->r()
#define PARAM_3 ctx->thread[RegisterAccessProxy::Register::R3]->r()
#define PARAM_4x(idx) ctx->coord.proxy().r<uint32_t>(ctx->thread[RegisterAccessProxy::Register::SP]->r() + (idx - 4) * sizeof(uint32_t))

static inline void _target_return_impl(InterruptContext *ctx, uint32_t val)
{
    ctx->thread[RegisterAccessProxy::Register::R0]->w(val);
    ctx->thread[RegisterAccessProxy::Register::PC]->w(ctx->thread[RegisterAccessProxy::Register::LR]->r());
}

#define TARGET_RETURN(val) _target_return_impl(ctx, val)
#define HANDLER_RETURN(val) return std::make_shared<HandlerResult>(val)
#define HANDLER_EXCEPTION(excp) return std::make_shared<HandlerException<decltype(excp)>>(excp)
#define HANDLER_RUNTIME_EXCEPTION(what) HANDLER_EXCEPTION(std::runtime_error(what))

#define _FORWARD_PASTE(a) a
#define DECLARE_VITA_IMP_TYPE(type) \
    if (!ctx)                       \
    HANDLER_RETURN(ProviderPokeResult::_FORWARD_PASTE(type))

#define VITA_IMP_NID_FORWARD_SYM(libraryNID, functionNID, target) \
    DEFINE_VITA_IMP_NID_EXPORT(libraryNID, functionNID)           \
    {                                                             \
        DECLARE_VITA_IMP_TYPE(FUNCTION);                          \
        return ctx->install_forward_handler(target);              \
    }

static inline uint32_t PARAM(InterruptContext *ctx, uint32_t idx) /* slow */
{
    switch (idx)
    {
    case 0:
        return ctx->thread[RegisterAccessProxy::Register::R0]->r();
    case 1:
        return ctx->thread[RegisterAccessProxy::Register::R1]->r();
    case 2:
        return ctx->thread[RegisterAccessProxy::Register::R2]->r();
    case 3:
        return ctx->thread[RegisterAccessProxy::Register::R3]->r();
    default:
        return ctx->coord.proxy().r<uint32_t>(ctx->thread[RegisterAccessProxy::Register::SP]->r() + (idx - 4) * sizeof(uint32_t));
    }
}

#endif
