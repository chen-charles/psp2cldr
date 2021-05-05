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

static const char INSTR_BPKT3_BXLR_ARM[]{"\x73\x00\x20\xe1\x1e\xff\x2f\xe1"};
static const char INSTR_BKPT3_BXLR_THM[]{"\x03\xbe\x70\x47"};

// use UDF instructions to generate interruption, instead of using BKPT
static const char INSTR_UND0_BXLR_ARM[]{"\xf0\x00\xf0\xe7\x1e\xff\x2f\xe1"};
static const char INSTR_UND0_BXLR_THM[]{"\x00\xde\x70\x47"};

static void install_nid_stub(LoadContext &ctx, MemoryAccessProxy &proxy, uint32_t libraryNID, uint32_t functionNID, uint32_t ptr_f, unimplemented_nid_handler stub_func)
{
    if (ptr_f & 1) // thumb
        proxy.copy_in(ptr_f & (~1), INSTR_UND0_BXLR_THM, sizeof(INSTR_UND0_BXLR_THM));
    else
        proxy.copy_in(ptr_f, INSTR_UND0_BXLR_ARM, sizeof(INSTR_UND0_BXLR_ARM));

    nid_stub stub;
    stub.libraryNID = libraryNID;
    stub.functionNID = functionNID;
    stub.func = stub_func;
    ctx.unimplemented_targets[ptr_f] = stub;
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
            if (ctx.nid_overrides.count(nid_hash(libraryNID, functionNID)) != 0)
                continue;
            else if (ctx.provider() && ctx.provider()->get(libraryNID, functionNID))
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
    for (auto &imp : imps)
    {
        auto libraryNID = imp.first;
        for (auto &ent : imp.second)
        {
            auto functionNID = ent.first;
            auto ptr_f = velf.va2la(ent.second, load_base);
            assert(ptr_f != -1);

            if (ctx.nid_overrides.count(nid_hash(libraryNID, functionNID)) != 0)
            {
                install_nid_stub(ctx, proxy, libraryNID, functionNID, ptr_f, ctx.nid_overrides[nid_hash(libraryNID, functionNID)]);
            }
            else if (ctx.provider() && ctx.provider()->get(libraryNID, functionNID))
            {
                install_nid_stub(ctx, proxy, libraryNID, functionNID, ptr_f,
                                 [](NID_t libraryNID, NID_t functionNID, InterruptContext *ctx) {
                                     return ctx->load.provider()->get(libraryNID, functionNID)(ctx);
                                 });
            }
            else if (ctx.nids_export_locations.count(nid_hash(libraryNID, functionNID)) != 0)
            {
                uintptr_t loc = ctx.nids_export_locations[nid_hash(libraryNID, functionNID)];

                if (ptr_f & 1) // thumb
                {
                    char thm_ldr_and_bx_r12[]{"\xdf\xf8\x04\xc0\x60\x47\x00\xbf\x00\x00\x00\x00"};
                    *(uint32_t *)(thm_ldr_and_bx_r12 + 8) = loc;
                    proxy.copy_in(ptr_f & (~1), thm_ldr_and_bx_r12, sizeof(thm_ldr_and_bx_r12) - 1);
                }
                else
                {
                    char arm_ldr_and_bx_r12[]{"\x00\xc0\x9f\xe5\x1c\xff\x2f\xe1\x00\x00\x00\x00"};
                    *(uint32_t *)(arm_ldr_and_bx_r12 + 8) = loc;
                    proxy.copy_in(ptr_f, arm_ldr_and_bx_r12, sizeof(arm_ldr_and_bx_r12) - 1);
                }
            }
            else
            {
                install_nid_stub(ctx, proxy, libraryNID, functionNID, ptr_f,
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
            auto ptr_f = velf.va2la(ent.second, load_base);

            if (libraryNID == 0x0 && functionNID == 0x935CD196)
            {
                module_start = ptr_f;
                LOG(TRACE, "module_start va={:#010x} la={:#010x}", ent.second, module_start);
                break;
            }
        }
    }

    if (!module_start)
        throw std::runtime_error("module_start is not exported");

    LOG(DEBUG, "preparing execution environment for module_start");
    auto thread = coordinator.thread_create();

    thread->register_interrupt_callback(
        [&ctx](ExecutionCoordinator &coord, ExecutionThread &thread, uint32_t intno) {
            InterruptContext intr_ctx(coord, thread, ctx);
            auto pc = thread[RegisterAccessProxy::Register::PC]->r();
            if (intno == POSIX_SIGILL)
            {
                if (thread[RegisterAccessProxy::Register::CPSR]->r() & (1 << 5))
                    pc |= 1;

                if (ctx.unimplemented_targets.count(pc) != 0)
                {
                    auto entry = ctx.unimplemented_targets.at(pc);
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

    uint32_t sp = coordinator.mmap(0, 0x4000) + 0x4000;
    //using enum RegisterAccessProxy::Register;   // C++20
    (*thread)[RegisterAccessProxy::Register::SP]->w(sp);
    LOG(TRACE, "stack top={:#010x}, size={:#010x}", sp, 0x4000);
    uint32_t lr = coordinator.mmap(0, 0x1000);
    (*thread)[RegisterAccessProxy::Register::LR]->w(lr);

    LOG(DEBUG, "calling module_start at {:#010x}, until {:#010x}", module_start, lr);
    uint32_t module_start_result;
    if (thread->start(module_start, lr) != ExecutionThread::THREAD_EXECUTION_RESULT::OK || (*thread).join(&module_start_result) != ExecutionThread::THREAD_EXECUTION_RESULT::STOP_UNTIL_POINT_HIT || module_start_result != 0)
    {
        coordinator.thread_destory(thread);
        LOG(ERROR, "module load failed because module_start failed");
        return 4;
    }
    coordinator.thread_destory(thread);

    LOG(DEBUG, "exporting exports");
    for (auto &exp : exps)
    {
        auto libraryNID = exp.first;
        for (auto &ent : exp.second)
        {
            auto functionNID = ent.first;
            auto ptr_f = velf.va2la(ent.second, load_base);

            if (libraryNID != 0x0)
            {
                ctx.nids_export_locations[nid_hash(libraryNID, functionNID)] = ptr_f;
            }
        }
    }

    LOG(INFO, "VELF \"{}\" load end", filename);
    return 0;
}

#include <psp2cldr/arm_elfloader.hpp>
static void install_sym_stub(LoadContext &ctx, ExecutionCoordinator &coordinator, std::string sym_name, Elf32_Sym sym, uint32_t ptr_f, unimplemented_sym_handler stub_func)
{
    static uint32_t handler_stub_loc = coordinator.mmap(0, 0x4000);
    auto &proxy = coordinator.proxy();

    proxy.copy_in(handler_stub_loc, INSTR_UND0_BXLR_ARM, sizeof(INSTR_UND0_BXLR_ARM) - 1);

    sym_stub stub;
    stub.name = sym_name;
    stub.sym = sym;
    stub.func = stub_func;

    ctx.unimplemented_targets[handler_stub_loc] = stub;
    proxy.w<uint32_t>(ptr_f, handler_stub_loc);
    handler_stub_loc += sizeof(INSTR_UND0_BXLR_ARM) - 1;
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
    for (auto &imp : elf.get_imports())
    {
        std::string sym_name{elf.getstr(imp.first.st_name)};

        auto ptr_f = elf.va2la(imp.second, load_base);

        if (ctx.sym_overrides.count(sym_name) != 0)
        {
            install_sym_stub(ctx, coordinator, sym_name, imp.first, ptr_f, ctx.sym_overrides[sym_name]);
        }
        else if (ctx.provider() && ctx.provider()->get(sym_name.c_str()))
        {
            install_sym_stub(ctx, coordinator, sym_name, imp.first, ptr_f, [](std::string name, Elf32_Sym sym, InterruptContext *ctx) {
                return ctx->load.provider()->get(name.c_str())(ctx);
            });
        }
        else if (ctx.libs_export_locations.count(sym_name) != 0)
        {
            /* got stores a ptr instead of a stub */
            auto exist_sym = ctx.libs_export_locations[sym_name];
            proxy.w<uint32_t>(ptr_f, exist_sym.second);
        }
        else
        {
            install_sym_stub(ctx, coordinator, sym_name, imp.first, ptr_f, [](std::string name, Elf32_Sym sym, InterruptContext *ctx) {
                LOG(CRITICAL, "import stub for {} is hit, unimplemented", name);
                return std::make_shared<HandlerResult>(1);
            });
        }
    }

    auto init_routines = elf.get_init_routines(proxy, load_base);
    if (!init_routines.empty())
    {
        LOG(DEBUG, "preparing execution environment for init");
        auto thread = coordinator.thread_create();

        thread->register_interrupt_callback(
            [&ctx](ExecutionCoordinator &coord, ExecutionThread &thread, uint32_t intno) {
                InterruptContext intr_ctx(coord, thread, ctx);
                auto pc = thread[RegisterAccessProxy::Register::PC]->r();
                if (intno == POSIX_SIGILL)
                {
                    if (thread[RegisterAccessProxy::Register::CPSR]->r() & (1 << 5))
                        pc |= 1;

                    if (ctx.unimplemented_targets.count(pc) != 0)
                    {
                        auto entry = ctx.unimplemented_targets.at(pc);
                        LOG(TRACE, "handler: {}", entry.repr());
                        auto handler_result = entry.call(&intr_ctx);
                        LOG(TRACE, "handler exit: {}", entry.repr());
                        if (handler_result->result() == 0)
                            return;
                        else
                        {
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

        uint32_t sp = coordinator.mmap(0, 0x4000) + 0x4000;
        (*thread)[RegisterAccessProxy::Register::SP]->w(sp);
        uint32_t lr = coordinator.mmap(0, 0x1000);
        (*thread)[RegisterAccessProxy::Register::LR]->w(lr);

        for (auto &la : init_routines)
        {
            LOG(DEBUG, "calling init_routine at {:#010x}, until {:#010x}", la, lr);
            uint32_t init_result;
            if (thread->start(la, lr) != ExecutionThread::THREAD_EXECUTION_RESULT::OK || (*thread).join(&init_result) != ExecutionThread::THREAD_EXECUTION_RESULT::STOP_UNTIL_POINT_HIT || init_result != 0)
            {
                coordinator.thread_destory(thread);
                LOG(ERROR, "module load failed because init_routine failed");
                return 4;
            }
        }
        coordinator.thread_destory(thread);
    }

    std::vector<std::pair<std::string, std::pair<Elf32_Sym, uint32_t>>> to_export;
    LOG(DEBUG, "exporting exports");
    auto exps = elf.get_exports();
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
        ctx.libs_export_locations[entry.first] = entry.second;
        if (entry.first == "_start")
        {
            /* make sure _exit is not called, otherwise newlib shuts down */
        }
    }

    LOG(INFO, "ELF \"{}\" load end", filename);
    return 0;
}
