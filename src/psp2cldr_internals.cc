/* __psp2cldr__internal_* routine implementations */
#include <psp2cldr/imp_provider.hpp>

#include <mutex>
#include <psp2cldr/logger.hpp>

static std::mutex tls_mutex;
#undef __psp2cldr__internal_tls_ctrl
DEFINE_VITA_IMP_SYM_EXPORT(__psp2cldr__internal_tls_ctrl)
{
    DECLARE_VITA_IMP_TYPE(FUNCTION);
    /*
    0: retrieve tls ptr
    1: free tls
    */
    auto ctrl = PARAM_0;

    std::lock_guard guard(tls_mutex);

    static std::unordered_map<uint32_t, uint32_t> mapping;

    auto tid = ctx->thread.tid();

    switch (ctrl)
    {
    case 0:
        if (mapping.count(tid) == 0)
            mapping[tid] = ctx->coord.mmap(0, 0x1000);
        TARGET_RETURN(mapping[tid]);
        HANDLER_RETURN(0);
    case 1:
        if (mapping.count(tid) == 0)
        {
            LOG(CRITICAL, "attempted to free TLS, but it doesn't exist");
            HANDLER_RETURN(1);
        }
        ctx->coord.munmap(mapping[tid], 0x1000);
        mapping.erase(tid);
        TARGET_RETURN(0);
        HANDLER_RETURN(0);
        break;
    default:
        LOG(CRITICAL, "unrecognized ctrl value");
        HANDLER_RETURN(2);
    }
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
