/*
 * Copyright (C) 2021-2022 Jianye Chen
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

#include <psp2cldr/access_proxy.hpp>
#include <psp2cldr/context.hpp>
#include <psp2cldr/coordinator.hpp>
#include <psp2cldr/load.hpp>
#include <psp2cldr/logger.hpp>
#include <psp2cldr/provider.hpp>
#include <psp2cldr/velf.hpp>

#if defined(_MSC_VER) || (__GNUC__ >= 8)
#include <filesystem>
namespace fs = std::filesystem;
#else
#include <experimental/filesystem>
namespace fs = std::experimental::filesystem;
#endif

static const char INSTR_BPKT3_ARM[]{"\x73\x00\x20\xe1"};
static const char INSTR_BKPT3_THM[]{"\x03\xbe"};

// use UDF instructions to generate interruption, instead of using BKPT
static const uint32_t INSTR_UDF0_ARM = 0xe7f000f0;
static const uint16_t INSTR_UDF0_THM = 0xde00;

static std::shared_ptr<ExecutionThread> init_main_thread(LoadContext &ctx, ExecutionCoordinator &coordinator)
{
    static std::shared_ptr<ExecutionThread> thread;

    if (!thread)
    {
        LOG(DEBUG, "preparing execution environment for init");
        coordinator.register_interrupt_callback([&ctx](ExecutionCoordinator &coord, ExecutionThread &thread,
                                                       uint32_t intno) {
            InterruptContext intr_ctx(coord, thread, ctx);
            auto pc = thread[RegisterAccessProxy::Register::PC]->r();
            if (intno == POSIX_SIGILL)
            {
                if (thread[RegisterAccessProxy::Register::CPSR]->r() & (1 << 5))
                    pc |= 1;
                bool entry_exists = false;
                import_stub_entry entry;
                {
                    std::shared_lock guard(ctx.unimplemented_targets_mutex);
                    if (ctx.unimplemented_targets.count(pc) != 0)
                    {
                        entry_exists = true;
                        entry = ctx.unimplemented_targets.at(pc);
                    }
                }

                if (entry_exists)
                {
                    LOG(TRACE, "handler({}): {}", thread.tid(), entry.repr());
                    auto handler_result = entry.call(&intr_ctx);
                    LOG(TRACE, "handler({}) exit: {}", thread.tid(), entry.repr());
                    if (const std::exception *handler_excp = handler_result->exception())
                    {
                        intr_ctx.panic(0xff, handler_excp->what());
                    }
                    else if (handler_result->result() == 0)
                        return;
                    else
                    {
                        LOG(CRITICAL, "handler {} returned {:#010x} != 0, die ...", entry.repr(),
                            handler_result->result());
                        intr_ctx.panic(1);
                    }
                }
                else
                {
                    LOG(CRITICAL, "unexpected SIGILL at {:#010x}, instr={:#010x}", pc, coord.proxy().r<uint32_t>(pc));
                    intr_ctx.panic(2);
                }
            }
            else
            {
                intr_ctx.panic(3);
            }
        });

        thread = coordinator.thread_create();
    }

    return thread;
}

static int call_from_main_thread(std::vector<uintptr_t> init_routines, LoadContext &ctx,
                                 ExecutionCoordinator &coordinator)
{
    // there is a single mainthread through the lifetime of an application
    // upon its exit, all subsequent threads are killed

    if (init_routines.empty())
        return 0;

    auto thread = init_main_thread(ctx, coordinator);

    static const size_t stack_sz = 0x200000; // 2 MB stack
    uint32_t sp_base = coordinator.mmap(0, stack_sz);
    uint32_t sp = sp_base + stack_sz;
    uint32_t lr = coordinator.mmap(0, 0x1000);

    size_t succ_counter = 0;
    for (auto &la : init_routines)
    {
        LOG(DEBUG, "calling init_routine at {:#010x}, until {:#010x}, stack_base {:#010x}", la, lr, sp_base);

        (*thread)[RegisterAccessProxy::Register::SP]->w(sp);
        (*thread)[RegisterAccessProxy::Register::LR]->w(lr);
        (*thread)[RegisterAccessProxy::Register::R0]->w(0);

        uint32_t result;
        if (thread->start(la, lr) != ExecutionThread::THREAD_EXECUTION_RESULT::OK ||
            (*thread).join(&result) != ExecutionThread::THREAD_EXECUTION_RESULT::STOP_UNTIL_POINT_HIT)
            break;
        if (sp != (*thread)[RegisterAccessProxy::Register::SP]->r())
        {
            LOG(WARN, "thread stack corruption detected");
            break;
        }

        succ_counter++;
    }

    coordinator.munmap(sp_base, stack_sz);
    coordinator.munmap(lr, 0x1000);

    return succ_counter;
}

static void install_nid_stub(LoadContext &ctx, MemoryAccessProxy &proxy, uint32_t libraryNID, uint32_t functionNID,
                             uint32_t ptr_f, bool in_place, unimplemented_nid_handler stub_func)
{
    uint32_t stub_location;
    if (in_place)
    {
        stub_location = ptr_f;
    }
    else
    {
        stub_location = proxy.r<uint32_t>(ptr_f);
    }

    if (stub_location & 1) // thumb
        proxy.copy_in(stub_location & (~1), &INSTR_UDF0_THM, sizeof(INSTR_UDF0_THM));
    else
        proxy.copy_in(stub_location, &INSTR_UDF0_ARM, sizeof(INSTR_UDF0_ARM));

    nid_stub stub;
    stub.libraryNID = libraryNID;
    stub.functionNID = functionNID;
    stub.func = stub_func;

    std::unique_lock guard(ctx.unimplemented_targets_mutex);
    ctx.unimplemented_targets[stub_location] = stub;
}

int load_velf(const std::string &filename, LoadContext &ctx, ExecutionCoordinator &coordinator)
{
    LOG(INFO, "VELF \"{}\" load begin", filename);
    VELF velf(filename.c_str());
    LOG(INFO, "module name: {}", velf.name());

    auto imps = velf.get_imports();
    for (auto &imp : imps)
    {
        auto libraryNID = imp.first;
        for (auto &ent : imp.second)
        {
            auto functionNID = ent.first;
            if (ctx.provider() && ctx.provider()->get(libraryNID, functionNID))
                continue;
            else if (ctx.nids_loaded.count(libraryNID) == 0)
            {
                if (ctx.nid_to_filename.count(libraryNID) != 0)
                {
                    fs::path nid_filename = ctx.nid_to_filename.at(libraryNID);
                    for (auto &search_path : ctx.search_paths)
                    {
                        fs::path library_path = search_path / nid_filename;
                        if (fs::exists(library_path))
                        {
                            if (load_velf(fs::absolute(library_path).string(), ctx, coordinator) != 0)
                                return 1; // subsequent load failed
                            break;
                        }
                    }
                }
#if 0
                else
                {
                    // does not exist; nor stub-ed
                    LOG(ERROR, "pre-load check failed, module {:#010x} is not provided", libraryNID, functionNID);
                    return 2;
                }
#endif
            }
            else if (ctx.nids_loaded[libraryNID].count(functionNID) == 0)
            {
                LOG(ERROR, "pre-load check failed, module {:#010x} is not providing {:#010x}", libraryNID, functionNID);
                return 3;
            }
            // pre-check, will install stubs later
        }
    }

    LOG(DEBUG, "loading and applying relocations");
    auto &proxy = coordinator.proxy();
    auto load_info = velf.load_and_relocate(
        [&coordinator](uint32_t addr, size_t len) { return coordinator.mmap(addr, len); }, proxy);
    auto &load_base = load_info.first;
    LOG(INFO, "load base={:#010x}, load top={:#010x}", load_base, load_base + load_info.second);

    LOG(DEBUG, "resolving imports");
    std::vector<uintptr_t> init_routines;
    for (auto &imp : imps)
    {
        auto libraryNID = imp.first;
        for (auto &ent : imp.second)
        {
            auto functionNID = ent.first;
            auto ptr_f = velf.va2la(ent.second, load_base);
            assert(ptr_f != -1);

            auto f_stub = proxy.r<uint32_t>(ptr_f);

            if (ctx.provider() && ctx.provider()->get(libraryNID, functionNID))
            {
                auto type_of_import = ctx.provider()->get(libraryNID, functionNID)(nullptr)->result();

                if (type_of_import == ProviderPokeResult::VARIABLE)
                {
                    install_nid_stub(ctx, proxy, libraryNID, functionNID, ptr_f, true,
                                     [](NID_t libraryNID, NID_t functionNID, InterruptContext *ctx) {
                                         return ctx->load.provider()->get(libraryNID, functionNID)(ctx);
                                     });
                    init_routines.push_back(ptr_f);
                }
                else
                {
                    install_nid_stub(ctx, proxy, libraryNID, functionNID, ptr_f, false,
                                     [](NID_t libraryNID, NID_t functionNID, InterruptContext *ctx) {
                                         return ctx->load.provider()->get(libraryNID, functionNID)(ctx);
                                     });
                }
            }
            else if (ctx.nids_export_locations.count(nid_hash(libraryNID, functionNID)) != 0)
            {
                auto &entry = ctx.nids_export_locations[nid_hash(libraryNID, functionNID)];
                bool is_variable = entry.first;
                uintptr_t loc = entry.second;

                if (is_variable)
                {
                    proxy.w<uint32_t>(ptr_f, loc);
                }
                else
                {
                    if (f_stub & 1) // thumb
                    {
                        char thm_ldr_and_bx_r12[]{"\xdf\xf8\x04\xc0\x60\x47\x00\xbf\x00\x00\x00\x00"};
                        *(uint32_t *)(thm_ldr_and_bx_r12 + 8) = loc;
                        proxy.copy_in(f_stub & (~1), thm_ldr_and_bx_r12, sizeof(thm_ldr_and_bx_r12) - 1);
                    }
                    else
                    {
                        char arm_ldr_and_bx_r12[]{"\x00\xc0\x9f\xe5\x1c\xff\x2f\xe1\x00\x00\x00\x00"};
                        *(uint32_t *)(arm_ldr_and_bx_r12 + 8) = loc;
                        proxy.copy_in(f_stub, arm_ldr_and_bx_r12, sizeof(arm_ldr_and_bx_r12) - 1);
                    }
                }
            }
            else
            {
                install_nid_stub(ctx, proxy, libraryNID, functionNID, ptr_f, false,
                                 [](NID_t libraryNID, NID_t functionNID, InterruptContext *ctx) {
                                     LOG(CRITICAL, "import stub for {:#010x}:{:#010x} is hit, unimplemented",
                                         libraryNID, functionNID);
                                     return std::make_shared<HandlerResult>(1);
                                 });
                LOG(TRACE, "import stub created for {:#010x}:{:#010x} at {:#010x}", libraryNID, functionNID, ptr_f);
            }
        }
    }

    // note: inaccurate, the actual entry might be a thumb instr., but this addr is always indicating an ARM instr.
    uintptr_t module_start = velf.off2la(velf.module_info.module_start, load_base);

    LOG(DEBUG, "finding module_start");
    auto exps = velf.get_exports();
    for (auto &exp : exps)
    {
        auto libraryNID = exp.first;
        for (auto &ent : exp.second)
        {
            auto functionNID = ent.first;
            auto ptr_f = velf.va2la(ent.second.second, load_base);

            if (libraryNID == 0x0 && functionNID == 0x935CD196)
            {
                module_start = ptr_f;
                LOG(TRACE, "module_start va={:#010x} la={:#010x}", ent.second.second, module_start);
                break;
            }
        }
    }

    if (!module_start)
        throw std::runtime_error("module_start is not exported");

    init_routines.push_back(module_start);

    if (call_from_main_thread(init_routines, ctx, coordinator) != init_routines.size())
    {
        LOG(ERROR, "module load failed because init_routines failed");
        return 4;
    }

    LOG(DEBUG, "exporting exports");
    for (auto &exp : exps)
    {
        auto libraryNID = exp.first;
        for (auto &ent : exp.second)
        {
            auto functionNID = ent.first;
            auto ptr_f = velf.va2la(ent.second.second, load_base);

            if (libraryNID != 0x0)
            {
                ctx.nids_export_locations[nid_hash(libraryNID, functionNID)] = std::make_pair(ent.second.first, ptr_f);
            }
        }
    }

    LOG(INFO, "VELF \"{}\" load end", filename);
    return 0;
}

#include <psp2cldr/arm_elfloader.hpp>
static void install_sym_stub(LoadContext &ctx, ExecutionCoordinator &coordinator, std::string sym_name, Elf32_Sym sym,
                             uint32_t ptr_f, bool in_place, unimplemented_sym_handler stub_func)
{
    auto &proxy = coordinator.proxy();

    uint32_t stub_location;
    if (!in_place)
    {
        static uint32_t handler_stub_loc = coordinator.mmap(0, 0x4000);
        stub_location = handler_stub_loc;
        handler_stub_loc += sizeof(INSTR_UDF0_ARM);

        proxy.w<uint32_t>(ptr_f, stub_location);
    }
    else
    {
        stub_location = ptr_f;
    }

    if (stub_location & 1)
        proxy.w<uint32_t>(stub_location & (~1), INSTR_UDF0_THM);
    else
        proxy.w<uint32_t>(stub_location, INSTR_UDF0_ARM);

    sym_stub stub;
    stub.name = sym_name;
    stub.sym = sym;
    stub.func = stub_func;

    {
        std::unique_lock guard(ctx.unimplemented_targets_mutex);
        ctx.unimplemented_targets[stub_location] = stub;
    }
}

int load_elf(const std::string &filename, LoadContext &ctx, ExecutionCoordinator &coordinator)
{
    LOG(INFO, "ELF \"{}\" load begin", filename);

    ELF elf(filename);

    for (auto &libname : elf.get_import_libraries())
    {
        if (ctx.libs_loaded.count(libname) != 0)
            continue;
        else
        {
            fs::path lib = libname;
            for (auto &search_path : ctx.search_paths)
            {
                fs::path library_path = search_path / lib;
                if (fs::exists(library_path))
                {
                    if (load_elf(fs::absolute(library_path).string(), ctx, coordinator) != 0)
                        return 1; // subsequent load failed
                    break;
                }
            }
        }
    }

    LOG(DEBUG, "loading and applying relocations");
    auto &proxy = coordinator.proxy();
    auto load_info =
        elf.load_and_relocate([&coordinator](uint32_t addr, size_t len) { return coordinator.mmap(addr, len); }, proxy);
    auto &load_base = load_info.first;
    LOG(INFO, "load base={:#010x}, load top={:#010x}", load_base, load_base + load_info.second);

    /* constructors might throw exceptions */
    ctx.libs_loaded[filename] = load_info;
    uint32_t exidx_va, exidx_sz;
    if (elf.find_exidx(&exidx_va, &exidx_sz))
    {
        ctx.libs_exidx[filename] = {elf.va2la(exidx_va, load_base), exidx_sz};
    }

    LOG(DEBUG, "resolving imports");
    std::vector<uintptr_t> init_routines;
    for (auto &imp : elf.get_imports())
    {
        auto &sym = imp.first;
        std::string sym_name{elf.getstr(sym.st_name)};
        // ELF32_ST_TYPE(sym.st_info) is recorded in the exports; the importer has no knowledge of it
        auto ptr_f = elf.va2la(imp.second, load_base);

        if (ctx.provider() && ctx.provider()->get(sym_name.c_str()))
        {
            auto type_of_import = ctx.provider()->get(sym_name.c_str())(nullptr)->result();

            if (type_of_import == ProviderPokeResult::VARIABLE)
            {
                install_sym_stub(ctx, coordinator, sym_name, imp.first, ptr_f, true,
                                 [](std::string name, Elf32_Sym sym, InterruptContext *ctx) {
                                     return ctx->load.provider()->get(name.c_str())(ctx);
                                 });
                init_routines.push_back(ptr_f);
            }
            else
            {
                install_sym_stub(ctx, coordinator, sym_name, imp.first, ptr_f, false,
                                 [](std::string name, Elf32_Sym sym, InterruptContext *ctx) {
                                     return ctx->load.provider()->get(name.c_str())(ctx);
                                 });
            }
        }
        else if (ctx.libs_export_locations.count(sym_name) != 0)
        {
            /* got stores a ptr instead of a stub */
            auto exist_entry = ctx.libs_export_locations[sym_name];
            auto &exist_sym = exist_entry.first;

            proxy.w<uint32_t>(ptr_f, exist_entry.second);
            if (ELF32_ST_VISIBILITY(exist_sym.st_other) == STV_DEFAULT)
            {
                // preemptable
                ctx.libs_preemptable_symbols[sym_name].push_back(ptr_f);
            }
        }
        else
        {
            if (ELF32_ST_BIND(sym.st_info) == STB_WEAK)
            {
                ctx.libs_preemptable_symbols[sym_name].push_back(ptr_f);
                if (sym.st_shndx == SHN_UNDEF)
                    LOG(TRACE, "weak import \"{}\" might need a definition",
                        sym_name); // it is perfectly fine to not exist, however
            }
            else
                // TODO: remove, since the importer does not know if the stub is installed on a ptr to a variable
                install_sym_stub(ctx, coordinator, sym_name, imp.first, ptr_f, false,
                                 [](std::string name, Elf32_Sym sym, InterruptContext *ctx) {
                                     if (ctx->load.libs_export_locations.count(name) == 0)
                                     {
                                         LOG(CRITICAL, "import stub for {} is hit, unimplemented", name);
                                         return std::make_shared<HandlerResult>(1);
                                     }
                                     else
                                     {
                                         return std::dynamic_pointer_cast<HandlerResult>(
                                             ctx->handler_call_target_function(name)->then(
                                                 [](uint32_t result, InterruptContext *ctx) {
                                                     ctx->thread[RegisterAccessProxy::Register::PC]->w(
                                                         ctx->thread[RegisterAccessProxy::Register::LR]->r());
                                                     return std::make_shared<HandlerResult>(0);
                                                 }));
                                     }
                                 });
        }
    }

    uint32_t ptr__start = 0;
    LOG(DEBUG, "checking exports for provider overrides");
    auto exps = elf.get_exports();
    for (auto &exp : exps)
    {
        std::string exp_name{elf.getstr(exp.first.st_name)};
        auto ptr_f = elf.va2la(exp.second, load_base);

        if (ctx.provider() && ctx.provider()->get(exp_name))
        {
            auto type_of_import = ctx.provider()->get(exp_name)(nullptr)->result();

            if (type_of_import == ProviderPokeResult::VARIABLE)
            {
                /* it is possible, the symbol just needs to be weak */
                throw std::logic_error("cannot override variables, because the symbol only holds a pointer value");
            }
            else
            {
                install_sym_stub(ctx, coordinator, exp_name, exp.first, ptr_f, true,
                                 [](std::string name, Elf32_Sym sym, InterruptContext *ctx) {
                                     return ctx->load.provider()->get(name.c_str())(ctx);
                                 });
            }
        }

        if (exp_name == "_start")
        {
            /* DEPRECATION */
            /* make sure _exit is not called, otherwise newlib shuts down */
            LOG(WARN,
                "ELF \"{}\" is exporting \"_start\", is it compiled as an executable instead of a shared library?",
                filename);
            LOG(WARN,
                "If it is indeed a shared library, please use \"static void __attribute__((constructor))\" instead. ");
            ptr__start = ptr_f;
        }
    }

    auto elf_init_routines = elf.get_init_routines(proxy, load_base);
    std::move(elf_init_routines.begin(), elf_init_routines.end(), std::back_inserter(init_routines));

    if (ptr__start != 0)
    {
        init_routines.push_back(ptr__start);
    }

    if (call_from_main_thread(init_routines, ctx, coordinator) != init_routines.size())
    {
        LOG(ERROR, "module load failed because init_routine failed");
        return 4;
    }

    auto elf_term_routines = elf.get_term_routines(proxy, load_base);
    std::move(elf_term_routines.begin(), elf_term_routines.end(), std::back_inserter(ctx.mainthread_fini_routines));

    std::vector<std::pair<std::string, std::pair<Elf32_Sym, uint32_t>>> to_export;
    LOG(DEBUG, "exporting exports");
    for (auto &exp : exps)
    {
        auto sym = exp.first;
        std::string exp_name = elf.getstr(sym.st_name);
        auto ptr_f = elf.va2la(exp.second, load_base);

        if (ELF32_ST_BIND(sym.st_info) == STB_LOCAL || ELF32_ST_VISIBILITY(sym.st_other) == STV_HIDDEN)
            continue;

        if (ctx.libs_export_locations.count(exp_name) != 0)
        {
            auto prev_entry = ctx.libs_export_locations[exp_name];
            auto prev_sym = prev_entry.first;
            if (ELF32_ST_VISIBILITY(prev_sym.st_other) == STV_PROTECTED)
            {
                LOG(ERROR, "module load failed because a protected symbol is being preempted");
                return 5;
            }

            if (ELF32_ST_BIND(sym.st_info) != STB_GLOBAL)
            {
                // weak symbols does not preempt a prev. defined weak symbol
                continue;
            }
        }

        // notify everyone else (either linked with prev. def., or weak imports)
        if (ctx.libs_preemptable_symbols.count(exp_name))
        {
            for (auto &prev_linked : ctx.libs_preemptable_symbols[exp_name])
            {
                proxy.w<uint32_t>(prev_linked, ptr_f);
            }
            LOG(TRACE, "symbol \"{}\" is replaced", exp_name);
        }

        /* per-thread init. routines */
        static const char *MAGIC_thread_init = "__psp2cldr_init_";
        static const char *MAGIC_thread_fini = "__psp2cldr_fini_";
        if (exp_name.rfind(MAGIC_thread_init, 0) == 0)
        {
            ctx.thread_init_routines.push_back(ptr_f);
            if (call_from_main_thread({ptr_f}, ctx, coordinator) != 1)
            {
                LOG(ERROR, "module load failed because {} failed", exp_name);
                return 4;
            }
        }
        else if (exp_name.rfind(MAGIC_thread_fini, 0) == 0)
            ctx.thread_fini_routines.push_back(ptr_f);

        ctx.libs_export_locations[exp_name] = std::make_pair(sym, ptr_f);
    }

    LOG(INFO, "ELF \"{}\" load end", filename);
    return 0;
}
