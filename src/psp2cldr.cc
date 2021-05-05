#include <memory>
#if defined(_MSC_VER) || (__GNUC__ >= 8)
#include <filesystem>
namespace fs = std::filesystem;
#else
#include <experimental/filesystem>
namespace fs = std::experimental::filesystem;
#endif

#include <psp2cldr/context.hpp>
#include <psp2cldr/coordinator_impl.hpp>
#include <psp2cldr/load.hpp>
#include <psp2cldr/logger.hpp>
#include <psp2cldr/provider.hpp>
#include <psp2cldr/velf.hpp>

#include <psp2cldr/access_proxy.hpp>
#include <string>
#include <vector>

int main(int argc, char *argv[])
{
    auto console = spdlog::stdout_color_st("psp2cldr-console");
    console->set_pattern("%v");

    if (argc <= 1 || strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "--help") == 0)
    {
        const char usage_str[]{
            "\
usage: psp2cldr --readelf <filename> \n\
usage: psp2cldr <options> <filename> ...<nid_implementation_libraries> \n\
\n\
options: \n\
    -v[vvvv]: more verbose logging \n\
    --sys <target so>: specify a shared library or a directory of shared libraries to be loaded into the target environment \n\
    --syslst <target so list file>: specify a list of <target so> files to be loaded into the target environment \n\
    --libpath <dependency search path>: specify the search path of DT_NEEDED and other import libraries \n\
\n\
each of <nid_implementation_libraries> is one of the followings: \n\
    1. <dll>: a DLL \n\
    2. --querydll <dll>: a DLL using Query interface \n\
    3. --static: using statically linked implementation \n\
    4. <directory>: a directory of <dll>, searched recursively \n\
order of supplying <nid_implementation_libraries> matters, the first observance of an implementation will override the next one.\n\
"};
        console->info(usage_str);
        if (argc <= 1)
            return 1;
        else
            return 0;
    }

    if (argc == 3 && strcmp(argv[1], "--readelf") == 0)
    {
        VELF velf(argv[2]);

        console->info("module name: {}", velf.module_info.name);
        console->info("module NID: {:#010x}", velf.module_info.module_nid);
        console->info("module_start: {:#010x}", velf.module_info.module_start);
        console->info("module_stop: {:#010x}", velf.module_info.module_stop);

        console->info("Relocation(s) (fmt: [RelocationType] [location(P)])");
        for (auto &reloc : velf.relocations)
        {
            uint16_t code;
            uint32_t P;
            switch (reloc.r_short)
            {
            case 0: // long, 12 bytes
                code = reloc.r_long_entry.r_code;
                P = velf.find_seg_vabase(reloc.r_long_entry.r_datseg) + reloc.r_long_entry.r_offset;
                break;
            case 1: // short, 8 bytes
                code = reloc.r_short_entry.r_code;
                P = velf.find_seg_vabase(reloc.r_short_entry.r_datseg) + (reloc.r_short_entry.r_offset_hi << 12) + reloc.r_short_entry.r_offset_lo;
                break;
            default:
                throw std::out_of_range("relocation type is not implemented");
            }
            console->info("{:#010x}\t{:#010x}", code, P);
        }

        console->info("Export(s) (fmt: [libraryNID] [itemNID] [location])");
        for (auto &exp : velf.get_exports())
        {
            for (auto &ent : exp.second)
            {
                console->info("{:#010x}\t{:#010x}\t{:#010x}", exp.first, ent.first, ent.second);
            }
        }

        console->info("Import(s) (fmt: [libraryNID] [itemNID] [stubLocation])");
        for (auto &imp : velf.get_imports())
        {
            for (auto &ent : imp.second)
            {
                console->info("{:#010x}\t{:#010x}\t{:#010x}", imp.first, ent.first, ent.second);
            }
        }

        return 0;
    }

    auto pool = std::make_shared<Provider_Pool>();
    int delta_verbosity = 0;
    bool velf_path_set = false;
    fs::path velf_path;
    std::vector<std::string> target_libraries;
    std::vector<std::string> search_paths;
    for (int i = 1; i < argc; i++)
    {
        if (argv[i][0] == '-') // argv[i][0] == 0 if the string is empty
        {
            if (strcmp(argv[i], "--static") == 0)
            {
                pool->add_provider(std::make_shared<Provider_StaticallyLinkedLibrary>());
                continue;
            }

            if (strcmp(argv[i], "--querydll") == 0)
            {
                if (i != argc - 1)
                {
                    pool->add_provider(std::make_shared<Provider_DynamicallyLinkedLibrary_Query>(fs::absolute(argv[++i]).string()));
                }
                continue;
            }

            if (strcmp(argv[i], "--libpath") == 0)
            {
                auto libpath = fs::absolute(argv[++i]);
                if (fs::is_directory(libpath))
                    search_paths.push_back(libpath.string());
                else
                    LOG(WARN, "ignored --libpath {} because it is not a directory", libpath.string());
                continue;
            }

            if (strcmp(argv[i], "--sys") == 0)
            {
                fs::path arg = fs::absolute(argv[++i]);
                if (!fs::exists(arg))
                {
                    throw std::invalid_argument("path does not exist");
                }
                LOG(INFO, "Target Library at {}", arg.string());
                target_libraries.push_back(arg.string());
                continue;
            }

            if (strcmp(argv[i], "--syslst") == 0)
            {
                fs::path arg = fs::absolute(argv[++i]);
                if (!fs::exists(arg))
                {
                    throw std::invalid_argument("path does not exist");
                }
                std::ifstream lst(arg);
                if (lst.is_open())
                {
                    std::string line;
                    while (std::getline(lst, line))
                    {
                        fs::path filename = fs::absolute(line);
                        if (!fs::exists(filename))
                        {
                            throw std::invalid_argument("path does not exist");
                        }
                        LOG(INFO, "Target Library at {}", filename.string());
                        target_libraries.push_back(filename.string());
                    }
                    lst.close();
                }
                else
                {
                    LOG(WARN, "specified sys list file {} does not exist", arg.string());
                }
                continue;
            }
            if (strncmp(argv[i], "-v", 2) == 0)
            {
                int v_count = 0;
                for (int j = 1;; j++)
                {
                    if (argv[i][j] == 0)
                        break;
                    if (argv[i][j] == 'v')
                        v_count++;
                    else
                    {
                        v_count = 0;
                        break;
                    }
                }
                if (v_count != 0)
                {
                    delta_verbosity += v_count;
                    continue;
                }
                // else, parse failed
            }
            LOG(WARN, "unrecognized option: {}", argv[i]);
        }

        fs::path arg = fs::absolute(argv[i]);
        if (!fs::exists(arg))
        {
            throw std::invalid_argument("path does not exist");
        }

        if (!velf_path_set)
        {
            velf_path_set = true;
            velf_path = arg;
            continue;
        }

        if (fs::is_directory(arg))
        {
            for (auto &p : fs::recursive_directory_iterator(arg))
            {
                auto pp = fs::absolute(p.path());
                if (fs::is_regular_file(pp))
                {
                    LOG(INFO, "Provider DLL at {}", pp.string());
                    pool->add_provider(std::make_shared<Provider_DynamicallyLinkedLibrary>(pp.string()));
                }
            }
        }
        else if (fs::is_regular_file(arg))
        {
            LOG(INFO, "Provider DLL at {}", arg.string());
            pool->add_provider(std::make_shared<Provider_DynamicallyLinkedLibrary>(arg.string()));
        }
        else
        {
            LOG(WARN, "{} is not a regular file, skipped", argv[i]);
        }
    }

    while (delta_verbosity)
    {
        if (delta_verbosity > 0)
        {
            switch (spdlog::get_level())
            {
            case spdlog::level::trace:
                break;
            case spdlog::level::debug:
                spdlog::set_level(spdlog::level::trace);
                break;
            case spdlog::level::info:
                spdlog::set_level(spdlog::level::debug);
                break;
            case spdlog::level::warn:
                spdlog::set_level(spdlog::level::info);
                break;
            case spdlog::level::err:
                spdlog::set_level(spdlog::level::warn);
                break;
            case spdlog::level::critical:
                spdlog::set_level(spdlog::level::err);
                break;
            case spdlog::level::off:
                spdlog::set_level(spdlog::level::critical);
                break;
            default:
                assert(false);
            }
            delta_verbosity--;
        }
        else
        {
            switch (spdlog::get_level())
            {
            case spdlog::level::trace:
                spdlog::set_level(spdlog::level::debug);
                break;
            case spdlog::level::debug:
                spdlog::set_level(spdlog::level::info);
                break;
            case spdlog::level::info:
                spdlog::set_level(spdlog::level::warn);
                break;
            case spdlog::level::warn:
                spdlog::set_level(spdlog::level::err);
                break;
            case spdlog::level::err:
                spdlog::set_level(spdlog::level::critical);
                break;
            case spdlog::level::critical:
                spdlog::set_level(spdlog::level::off);
                break;
            case spdlog::level::off:
                break;
            default:
                assert(false);
            }
            delta_verbosity++;
        }
    }

    Coordinator_Impl coord;
    LoadContext ctx_load(pool);
    ctx_load.search_paths = search_paths;

    bool succ = true;
    for (auto &name : target_libraries)
        if (!(succ = (load_elf(name, ctx_load, coord) == 0)))
            break;

    if (succ)
        load_velf(velf_path.string(), ctx_load, coord);

    return 0;
}
