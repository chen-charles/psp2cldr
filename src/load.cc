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

static int call_init_routines(std::vector<uintptr_t> init_routines, LoadContext &ctx, ExecutionCoordinator &coordinator)
{
    if (init_routines.empty())
        return 0;

    LOG(DEBUG, "preparing execution environment for init");
    coordinator.register_interrupt_callback(
        [&ctx](ExecutionCoordinator &coord, ExecutionThread &thread, uint32_t intno) {
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
                    LOG(TRACE, "handler: {}", entry.repr());
                    auto handler_result = entry.call(&intr_ctx);
                    LOG(TRACE, "handler exit: {}", entry.repr());
                    if (handler_result->result() == 0)
                        return;
                    else
                    {
                        LOG(CRITICAL, "handler {} returned {:#010x} != 0, die ...", entry.repr(), handler_result->result());
                        coord.panic(1, &intr_ctx);
                    }
                }
                else
                {
                    LOG(CRITICAL, "unexpected SIGILL at {:#010x}, instr={:#010x}", pc, coord.proxy().r<uint32_t>(pc));
                    coord.panic(2, &intr_ctx);
                }
            }
            else
            {
                coord.panic(3, &intr_ctx);
            }
        });

    static const size_t stack_sz = 0x4000;
    uint32_t sp_base = coordinator.mmap(0, stack_sz);
    uint32_t sp = sp_base + stack_sz;
    uint32_t lr = coordinator.mmap(0, 0x1000);

    size_t succ_counter = 0;
    auto thread = coordinator.thread_create();
    for (auto &la : init_routines)
    {
        LOG(DEBUG, "calling init_routine at {:#010x}, until {:#010x}", la, lr);

        (*thread)[RegisterAccessProxy::Register::SP]->w(sp);
        (*thread)[RegisterAccessProxy::Register::LR]->w(lr);

        uint32_t result;
        if (thread->start(la, lr) != ExecutionThread::THREAD_EXECUTION_RESULT::OK || (*thread).join(&result) != ExecutionThread::THREAD_EXECUTION_RESULT::STOP_UNTIL_POINT_HIT)
            break;
        if (sp != (*thread)[RegisterAccessProxy::Register::SP]->r())
        {
            LOG(WARN, "thread stack corruption detected");
            break;
        }

        succ_counter++;
    }
    coordinator.thread_destory(thread);

    coordinator.munmap(sp_base, stack_sz);
    coordinator.munmap(lr, 0x1000);

    return succ_counter;
}

static void install_nid_stub(LoadContext &ctx, MemoryAccessProxy &proxy, uint32_t libraryNID, uint32_t functionNID, uint32_t ptr_f, bool in_place, unimplemented_nid_handler stub_func)
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
    auto load_base = velf.load_and_relocate(
        [&coordinator](uint32_t addr, size_t len) {
            return coordinator.mmap(addr, len);
        },
        proxy);
    LOG(INFO, "load base={:#010x}", load_base);

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
                                     LOG(CRITICAL, "import stub for {:#010x}:{:#010x} is hit, unimplemented", libraryNID, functionNID);
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

    init_routines.insert(init_routines.end(), ctx.thread_init_routines.begin(), ctx.thread_init_routines.end());
    init_routines.push_back(module_start);
    init_routines.insert(init_routines.end(), ctx.thread_fini_routines.begin(), ctx.thread_fini_routines.end());

    if (call_init_routines(init_routines, ctx, coordinator) != init_routines.size())
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
static void install_sym_stub(LoadContext &ctx, ExecutionCoordinator &coordinator, std::string sym_name, Elf32_Sym sym, uint32_t ptr_f, bool in_place, unimplemented_sym_handler stub_func)
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
    auto load_base = elf.load_and_relocate(
        [&coordinator](uint32_t addr, size_t len) {
            return coordinator.mmap(addr, len);
        },
        proxy);
    LOG(INFO, "load base={:#010x}", load_base);

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
                install_sym_stub(ctx, coordinator, sym_name, imp.first, ptr_f, true, [](std::string name, Elf32_Sym sym, InterruptContext *ctx) {
                    return ctx->load.provider()->get(name.c_str())(ctx);
                });
                init_routines.push_back(ptr_f);
            }
            else
            {
                install_sym_stub(ctx, coordinator, sym_name, imp.first, ptr_f, false, [](std::string name, Elf32_Sym sym, InterruptContext *ctx) {
                    return ctx->load.provider()->get(name.c_str())(ctx);
                });
            }
        }
        else if (ctx.libs_export_locations.count(sym_name) != 0)
        {
            /* got stores a ptr instead of a stub */
            auto exist_sym = ctx.libs_export_locations[sym_name];
            proxy.w<uint32_t>(ptr_f, exist_sym.second);
        }
        else
        {
            if (ELF32_ST_BIND(sym.st_info) & STB_WEAK)
                ;
            else
                // TODO: remove, since the importer does not know if the stub is installed on a ptr to a variable
                install_sym_stub(ctx, coordinator, sym_name, imp.first, ptr_f, false, [](std::string name, Elf32_Sym sym, InterruptContext *ctx) {
                    if (ctx->load.libs_export_locations.count(name) == 0)
                    {
                        LOG(CRITICAL, "import stub for {} is hit, unimplemented", name);
                        return std::make_shared<HandlerResult>(1);
                    }
                    else
                    {
                        return std::dynamic_pointer_cast<HandlerResult>(ctx->handler_call_target_function(name)->then([](uint32_t result, InterruptContext *ctx) {
                            ctx->thread[RegisterAccessProxy::Register::PC]->w(ctx->thread[RegisterAccessProxy::Register::LR]->r());
                            return std::make_shared<HandlerResult>(0);
                        }));
                    }
                });
        }
    }

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
                throw std::logic_error("cannot override variables, because the symbol only holds a pointer value");
            }
            else
            {
                install_sym_stub(ctx, coordinator, exp_name, exp.first, ptr_f, true, [](std::string name, Elf32_Sym sym, InterruptContext *ctx) {
                    return ctx->load.provider()->get(name.c_str())(ctx);
                });
            }
        }
    }

    init_routines.insert(init_routines.end(), ctx.thread_init_routines.begin(), ctx.thread_init_routines.end());

    auto elf_init_routines = elf.get_init_routines(proxy, load_base);
    std::move(elf_init_routines.begin(), elf_init_routines.end(), std::back_inserter(init_routines));

    init_routines.insert(init_routines.end(), ctx.thread_fini_routines.begin(), ctx.thread_fini_routines.end());

    if (call_init_routines(init_routines, ctx, coordinator) != init_routines.size())
    {
        LOG(ERROR, "module load failed because init_routine failed");
        return 4;
    }

    std::vector<std::pair<std::string, std::pair<Elf32_Sym, uint32_t>>> to_export;
    LOG(DEBUG, "exporting exports");
    for (auto &exp : exps)
    {
        auto exp_name = elf.getstr(exp.first.st_name);
        auto ptr_f = elf.va2la(exp.second, load_base);
        if (ctx.libs_export_locations.count(exp_name) != 0)
        {
            auto prev_entry = ctx.libs_export_locations[exp_name];
            auto Sym = prev_entry.first;
            if (ELF32_ST_VISIBILITY(Sym.st_other) == STV_PROTECTED)
            {
                LOG(ERROR, "module load failed because a protected symbol is being preempted");
                return 5;
            }
        }

        to_export.push_back(std::make_pair(exp_name, std::make_pair(exp.first, ptr_f)));
    }

    ctx.libs_loaded.insert(filename);
    for (auto &entry : to_export)
    {
        static const char *MAGIC_thread_init = "__psp2cldr_init_";
        static const char *MAGIC_thread_fini = "__psp2cldr_fini_";
        if (entry.first.rfind(MAGIC_thread_init, 0) == 0)
            ctx.thread_init_routines.push_back(entry.second.second);
        else if (entry.first.rfind(MAGIC_thread_fini, 0) == 0)
            ctx.thread_fini_routines.push_back(entry.second.second);
        else if (entry.first == "_start")
        {
            /* make sure _exit is not called, otherwise newlib shuts down */
            LOG(WARN, "ELF \"{}\" is exporting \"_start\", is it compiled as an executable instead of a shared library?", filename);
            LOG(WARN, "If it is indeed a shared library, please use \"static int __attribute__((constructor))\" instead. ");
            if (call_init_routines({entry.second.second}, ctx, coordinator) != 1)
            {
                LOG(ERROR, "module load failed because _start failed");
                return 4;
            }
        }
        ctx.libs_export_locations[entry.first] = entry.second;
    }

    LOG(INFO, "ELF \"{}\" load end", filename);
    return 0;
}
