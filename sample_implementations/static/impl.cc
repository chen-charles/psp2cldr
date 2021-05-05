#include <iostream>

#include <psp2cldr/imp_provider.hpp>

DECLARE_VITA_IMP_NID_EXPORT(88758561, 391b74b8, ksceDebugPrintf)
DEFINE_VITA_IMP_NID_EXPORT(88758561, 391b74b8)
{
    std::cout << "(static)ksceDebugPrintf_stage2:";
    uint32_t r0 = ctx->thread[RegisterAccessProxy::Register::R0]->r();
    char ch;
    do
    {
        ch = ctx->coord.proxy().r<char>(r0++);

    } while (ch && std::cout << ch);
    std::cout << std::endl;

    ctx->thread[RegisterAccessProxy::Register::PC]->w(ctx->thread[RegisterAccessProxy::Register::LR]->r());
    return 0;
}

DEFINE_VITA_IMP_NID_EXPORT(88758561, 391b74b7)
{
    std::cout << "(static)ksceDebugPrintf_stage1:" << std::endl;
    return ksceDebugPrintf(ctx);
}
