/*
 * Copyright (C) 2021-2022 Jianye Chen
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

#include <psp2cldr/context.hpp>

#include <psp2cldr/coordinator.hpp>
#include <psp2cldr/logger.hpp>

#include <cassert>
#include <exception>
#include <mutex>
#include <unordered_map>

static void adjust_stack_for_parameters(InterruptContext *ctx, int n_params, bool is_undo = false)
{
    if (n_params > 4)
    {
        int delta = -4 * (n_params - 4);
        if (is_undo)
            delta = -delta;
        ctx->thread[RegisterAccessProxy::Register::SP]->w(ctx->thread[RegisterAccessProxy::Register::SP]->r() + delta);
    }
}

static uint32_t allocate_stub_location(InterruptContext *ctx)
{
    static std::once_flag initialization_flag;

    static std::atomic<uint32_t> handler_stub_loc;
    static uint32_t handler_stub_top;
    static const size_t CONT_STUB_SIZE = 0x100000;

    // @TODO: put this onto coordinator using a tag
    std::call_once(initialization_flag, [&]() {
        handler_stub_loc = ctx->coord.mmap(0, CONT_STUB_SIZE);
        handler_stub_top = handler_stub_loc + CONT_STUB_SIZE;
    });

    const uint32_t allocated = handler_stub_loc.fetch_add(0x8);
    if (handler_stub_top <= allocated + 0x8)
        throw std::runtime_error("FIXME: handler_stub has limited capacity");
    return allocated;
}

static void install_stub(LoadContext &ctx, uint32_t stub_loc, const sym_stub &stub)
{
    std::unique_lock guard(ctx.unimplemented_targets_mutex);
    ctx.unimplemented_targets[stub_loc] = stub;
}

static std::shared_ptr<HandlerContinuation> _handler_call_target_function_impl(int n_params, uint32_t target_func_ptr,
                                                                               InterruptContext *ctx)
{
    static const uint32_t INSTR_UDF0_ARM = 0xe7f000f0;

    uint32_t stub_loc = allocate_stub_location(ctx);
    ctx->coord.proxy().copy_in(stub_loc, &INSTR_UDF0_ARM, sizeof(INSTR_UDF0_ARM));

    std::shared_ptr<HandlerContinuation> out = std::make_shared<HandlerContinuation>(0);

    sym_stub stub;
    stub.name = "__psp2cldr__handler_continuation_to_" + u32_str_repr(target_func_ptr);
    uint32_t original_lr = ctx->thread[RegisterAccessProxy::Register::LR]->r();

    uint32_t original_sp = ctx->thread[RegisterAccessProxy::Register::SP]->r();
    adjust_stack_for_parameters(ctx, n_params);

    stub.func = [original_lr, original_sp, out, n_params](std::string name, Elf32_Sym sym, InterruptContext *p_ctx) {
        auto r0 = p_ctx->thread[RegisterAccessProxy::Register::R0]->r();
        p_ctx->thread[RegisterAccessProxy::Register::LR]->w(original_lr);

        adjust_stack_for_parameters(p_ctx, n_params, true);

        if (original_sp != p_ctx->thread[RegisterAccessProxy::Register::SP]->r())
            throw std::runtime_error("stack corruption detected");

        return out->continue_(r0, p_ctx);
    };

    ctx->thread[RegisterAccessProxy::Register::PC]->w(target_func_ptr);
    ctx->thread[RegisterAccessProxy::Register::LR]->w(stub_loc);

    install_stub(ctx->load, stub_loc, stub);
    return out;
}

std::shared_ptr<HandlerContinuation> InterruptContext::handler_call_target_function_impl(int n_params,
                                                                                         NIDHASH_t nid_hash)
{
    if (load.nids_export_locations.count(nid_hash) == 0)
        throw std::logic_error("attempted to call an unregistered target function");
    if (load.nids_export_locations[nid_hash].first)
        throw std::logic_error("attempted to call a variable");
    return _handler_call_target_function_impl(n_params, load.nids_export_locations[nid_hash].second, this);
}

std::shared_ptr<HandlerContinuation> InterruptContext::handler_call_target_function_impl(int n_params, std::string name)
{
    if (load.libs_export_locations.count(name) == 0)
        throw std::logic_error("attempted to call an unregistered target function");
    return _handler_call_target_function_impl(n_params, load.libs_export_locations[name].second, this);
}

void InterruptContext::set_function_call_parameter(int idx, uint32_t value)
{
    switch (idx)
    {
    case 0:
        thread[RegisterAccessProxy::Register::R0]->w(value);
        break;
    case 1:
        thread[RegisterAccessProxy::Register::R1]->w(value);
        break;
    case 2:
        thread[RegisterAccessProxy::Register::R2]->w(value);
        break;
    case 3:
        thread[RegisterAccessProxy::Register::R3]->w(value);
        break;
    default:
        coord.proxy().w(thread[RegisterAccessProxy::Register::SP]->r() - 4 * (idx - 3), value);
    }
}

std::shared_ptr<HandlerResult> InterruptContext::install_forward_handler(std::string target)
{
    auto &proxy = coord.proxy();
    if (load.libs_export_locations.count(target))
    {
        auto loc = load.libs_export_locations[target].second;
        auto pc = thread[RegisterAccessProxy::Register::PC]->r() & (~1);
        bool isThumb = thread[RegisterAccessProxy::Register::CPSR]->r() & (1 << 5);
        if (isThumb)
        {
            char thm_ldr_and_bx_r12[]{"\xdf\xf8\x04\xc0\x60\x47\x00\xbf\x00\x00\x00\x00"};
            *(uint32_t *)(thm_ldr_and_bx_r12 + 8) = loc;
            proxy.copy_in(pc, thm_ldr_and_bx_r12, sizeof(thm_ldr_and_bx_r12) - 1);
        }
        else
        {
            char arm_ldr_and_bx_r12[]{"\x00\xc0\x9f\xe5\x1c\xff\x2f\xe1\x00\x00\x00\x00"};
            *(uint32_t *)(arm_ldr_and_bx_r12 + 8) = loc;
            proxy.copy_in(pc, arm_ldr_and_bx_r12, sizeof(arm_ldr_and_bx_r12) - 1);
        }

        thread[RegisterAccessProxy::Register::PC]->w(loc);

        std::unique_lock guard(load.unimplemented_targets_mutex);
        if (load.unimplemented_targets.count(pc | (isThumb ? 1 : 0)) == 0)
            // flagging a re-entry for a one-time handler installer, likely a corruption somewhere
            return std::make_shared<HandlerResult>(2);

        load.unimplemented_targets.erase(pc | (isThumb ? 1 : 0));
        return std::make_shared<HandlerResult>(0);
    }

    // target does not exist
    return std::make_shared<HandlerResult>(1);
}

std::string InterruptContext::read_str(uint32_t p_cstr) const
{
    if (p_cstr == 0)
        return "<<<NULL>>>";
    auto &proxy = coord.proxy();
    char ch;
    std::stringstream ss;
    while (ch = proxy.r<char>(p_cstr++))
        ss << ch;
    return ss.str();
}

std::pair<std::string, uint32_t> LoadContext::try_resolve_location(uint32_t location) const
{
    for (auto &entry : libs_loaded)
    {
        auto &lib_name = entry.first;
        auto &load_info = entry.second;
        if (location >= load_info.first && location < load_info.first + load_info.second)
        {
            return {lib_name, location - load_info.first};
        }
    }
    return {};
}

#ifdef _MSC_VER
#include <intrin.h>
#else
#include <signal.h>
#endif

static std::recursive_mutex GLOBAL_PANIC_LOCK;

void panic(ExecutionCoordinator *coord, ExecutionThread *thread, LoadContext *load, int code, const char *msg)
{
    GLOBAL_PANIC_LOCK.lock();

    coord->thread_stopall(code);
    PANIC_LOG("code={:#x}", code);
    if (msg)
    {
        PANIC_LOG("msg={}", msg);
    }

    if (thread)
    {
        PANIC_LOG("called from thread: {:#x}", thread->tid());
    }

    if (load)
    {
        PANIC_LOG("Loaded Modules");
        for (auto &entry : load->libs_loaded)
        {
            auto &lib_name = entry.first;
            auto &load_info = entry.second;
            PANIC_LOG("{:#010x}-{:#010x} {}", load_info.first, load_info.first + load_info.second, lib_name);
        }
    }

    coord->panic(code, load);
#ifdef _MSC_VER
    __debugbreak();
#else
    raise(SIGTRAP);
#endif
    throw std::runtime_error("panic called");
}

void InterruptContext::panic(int code, const char *msg)
{
    ::panic(&coord, &thread, &load, code, msg);
}

void ExecutionCoordinator::panic(ExecutionThread *thread, LoadContext *load, int code, const char *msg)
{
    ::panic(this, thread, load, code, msg);
}
