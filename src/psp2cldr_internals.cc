/* __psp2cldr__internal_* routine implementations */
#include <psp2cldr/imp_provider.hpp>

#include <mutex>
#include <psp2cldr/logger.hpp>

#undef __psp2cldr__internal_tls_alloc
DEFINE_VITA_IMP_SYM_EXPORT(__psp2cldr__internal_tls_alloc)
{
    DECLARE_VITA_IMP_TYPE(FUNCTION);

    TARGET_RETURN(ctx->thread.tls.alloc());
    HANDLER_RETURN(0);
}

#undef __psp2cldr__internal_tls_free
DEFINE_VITA_IMP_SYM_EXPORT(__psp2cldr__internal_tls_free)
{
    DECLARE_VITA_IMP_TYPE(FUNCTION);

    ctx->thread.tls.free(PARAM_0);

    TARGET_RETURN(0);
    HANDLER_RETURN(0);
}

#undef __psp2cldr__internal_tls_setvalue
DEFINE_VITA_IMP_SYM_EXPORT(__psp2cldr__internal_tls_setvalue)
{
    DECLARE_VITA_IMP_TYPE(FUNCTION);

    ctx->thread.tls.set(PARAM_0, PARAM_1);

    TARGET_RETURN(0);
    HANDLER_RETURN(0);
}

#undef __psp2cldr__internal_tls_getvalue
DEFINE_VITA_IMP_SYM_EXPORT(__psp2cldr__internal_tls_getvalue)
{
    DECLARE_VITA_IMP_TYPE(FUNCTION);

    TARGET_RETURN(ctx->thread.tls.get(PARAM_0));
    HANDLER_RETURN(0);
}

#include <psp2cldr/provider.hpp>
#undef __psp2cldr__internal_call_nid
DEFINE_VITA_IMP_SYM_EXPORT(__psp2cldr__internal_call_nid)
{
    DECLARE_VITA_IMP_TYPE(FUNCTION);
    uint32_t libraryNID = PARAM_0;
    uint32_t functionNID = PARAM_1;
    auto ptr = ctx->load.provider()->get(libraryNID, functionNID);
    if (!ptr)
    {
        // treat as a strong symbol
        LOG(CRITICAL, "__psp2cldr__internal_call_nid to {:#010x}:{:#010x} is hit, unimplemented", libraryNID, functionNID);
        HANDLER_RETURN(1);
    }
    return ptr(ctx);
}

#undef __psp2cldr__internal_call_sym
DEFINE_VITA_IMP_SYM_EXPORT(__psp2cldr__internal_call_sym)
{
    DECLARE_VITA_IMP_TYPE(FUNCTION);
    uint32_t p_c_str = PARAM_0;
    auto sym_name = ctx->read_str(p_c_str);
    auto ptr = ctx->load.provider()->get(sym_name);
    if (!ptr)
    {
        // treat as a strong symbol
        LOG(CRITICAL, "__psp2cldr__internal_call_sym to \"{}\" is hit, unimplemented", sym_name);
        HANDLER_RETURN(1);
    }
    return ptr(ctx);
}

#undef __gnu_Unwind_Find_exidx
DEFINE_VITA_IMP_SYM_EXPORT(__gnu_Unwind_Find_exidx)
{
    DECLARE_VITA_IMP_TYPE(FUNCTION);
    auto return_address = PARAM_0;
    auto pcount = PARAM_1;

    for (auto &entry : ctx->load.libs_loaded)
    {
        auto &lib_name = entry.first;
        auto &load_info = entry.second;
        if (return_address >= load_info.first && return_address < load_info.first + load_info.second)
        {
            if (ctx->load.libs_exidx.count(lib_name) != 0)
            {
                auto &exidx = ctx->load.libs_exidx.at(lib_name);

                ctx->coord.proxy().w<uint32_t>(pcount, exidx.second / 8);

                LOG(TRACE, "exidx requested for {:#010x}, retrieved from {}", return_address, lib_name);
                TARGET_RETURN(exidx.first);
                HANDLER_RETURN(0);
            }
        }
    }

    LOG(TRACE, "exidx requested for {:#010x}, lookup failed", return_address);
    TARGET_RETURN(0);
    HANDLER_RETURN(0);
}
