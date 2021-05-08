/* __psp2cldr__internal_* routine implementations */
#include <psp2cldr/imp_provider.hpp>

#include <mutex>
#include <psp2cldr/logger.hpp>

#undef __psp2cldr__internal_tls_ctrl
DEFINE_VITA_IMP_SYM_EXPORT(__psp2cldr__internal_tls_ctrl)
{
    DECLARE_VITA_IMP_TYPE(FUNCTION);
    /*
    0: retrieve tls ptr
    1: free tls
    */
    auto ctrl = PARAM_0;

    static std::unordered_map<uint32_t, uint32_t> mapping;
    static std::mutex _mutex;
    auto tid = ctx->thread.tid();

    std::lock_guard guard(_mutex);
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
