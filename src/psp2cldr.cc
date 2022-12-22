/*
 * Copyright (C) 2021-2022 Jianye Chen
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

#include <memory>
#if defined(_MSC_VER) || (__GNUC__ >= 8)
#include <filesystem>
namespace fs = std::filesystem;
#else
#include <experimental/filesystem>
namespace fs = std::experimental::filesystem;
#endif

#include <psp2cldr/context.hpp>
#include <psp2cldr/implementation/coordinator.hpp>
#include <psp2cldr/implementation/load.hpp>
#include <psp2cldr/implementation/logger.hpp>
#include <psp2cldr/implementation/velf.hpp>
#include <psp2cldr/provider.hpp>

#include <psp2cldr/access_proxy.hpp>
#include <string>
#include <vector>

int main(int argc, char *argv[])
{
	auto console = spdlog::stdout_color_st("psp2cldr-console");
	console->set_pattern("%v");

	if (argc <= 1 || strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "--help") == 0)
	{
		// clang-format off
        const char usage_str[]{"\
usage: psp2cldr --readelf <velf> \n\
usage: psp2cldr [<options>] [--begin <additional options> --end] [<nid implementation library>...] \n\
\n\
<options>: \n\
    unless otherwise stated, options can be specified multiple times, and will be applied in order. \n\
\n\
    -v[v]: more verbose logging (in debug builds only) \n\
\n\
    --sys <target so>: specify a shared library or a directory of shared libraries to be loaded into the target environment \n\
    --syslst <target so list file>: specify a list of <target so>s to be loaded into the target environment \n\
    --sysprefix <path>: specify the pathing prefix to <target so>s, if not specified, default to getcwd() \n\
        applied in reverse \n\
\n\
    --velf <velf>: specify a VELF to load, VELFs will be loaded after ALL <target so>s \n\
\n\
    --querydll <dll>: see <nid implementation library> \n\
\n\
<additional options>: \n\
    <nid implementation library>s may accept additional options. psp2cldr will not interpret them in any way. \n\
    Additional options cannot be repeated. The last observance supersedes earlier ones. \n\
    All additional options should be in the form of '<KEY> <VALUE>', where <KEY> starts with '--'. \n\
    See their manuals for more details. \n\
\n\
<nid implementation library> is one of the followings: \n\
    1. <dll>: a DLL \n\
    2. --querydll <dll> from <options>: a DLL using the Query interface \n\
    3. <directory>: a directory of <dll>, searched recursively \n\
\n\
    order of supplying <nid implementation library> matters, the last observance of an implementation will supersede the earlier ones. \n\
"};
		// clang-format on

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
				console->info("{:#010x}\t{:#010x}\t{:#010x}", exp.first, ent.first, ent.second.second);
			}
		}

		console->info("Import(s) (fmt: [libraryNID] [itemNID] [ptr_f])");
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

	Coordinator_Impl coord;
	LoadContext ctx_load(pool);

	int delta_verbosity = 0;
	std::vector<std::string> sys_libraries;
	std::vector<fs::path> sys_prefixes;
	std::vector<fs::path> velfs;
	bool is_in_additional_options = false;
	std::unordered_map<std::string, std::string> &additional_options = ctx_load.additional_options;

	for (int i = 1; i < argc; i++)
	{
		const std::string arg{argv[i]};

		if (is_in_additional_options)
		{
			if (arg.compare("--end") == 0)
			{
				is_in_additional_options = false;
				continue;
			}
			additional_options[arg] = argv[++i];
			LOG(INFO, "Additional Option {}={}", arg, additional_options[arg]);
			continue;
		}

		if (arg.rfind("-v", 0) == 0)
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
			}
		}
		else if (arg.rfind("--", 0) == 0)
		{
			if (arg.compare("--querydll") == 0)
			{
				pool->add_provider(std::make_shared<Provider_DynamicallyLinkedLibrary_Query>(fs::absolute(argv[++i]).string()));
			}
			else if (arg.compare("--sysprefix") == 0)
			{
				auto path = fs::absolute(argv[++i]);
				if (fs::is_directory(path))
					sys_prefixes.push_back(std::move(path));
				else
					LOG(WARN, "sysprefix {} ignored because it is not a directory", path.string());
			}
			else if (arg.compare("--sys") == 0)
			{
				sys_libraries.push_back(argv[++i]);
			}
			else if (arg.compare("--syslst") == 0)
			{
				fs::path arg_path = fs::absolute(argv[++i]);
				if (!fs::exists(arg_path))
				{
					throw std::invalid_argument("path does not exist");
				}
				std::ifstream lst(arg_path);
				if (lst.is_open())
				{
					std::string line;
					while (std::getline(lst, line))
					{
						if (line.size() && line.rfind("#", 0) != 0)
						{
							sys_libraries.push_back(line);
						}
					}
					lst.close();
				}
				else
				{
					LOG(WARN, "specified sys list file {} does not exist", arg);
				}
			}
			else if (arg.compare("--velf") == 0)
			{
				velfs.push_back(fs::absolute(argv[++i]));
			}
			else if (arg.compare("--begin") == 0)
			{
				is_in_additional_options = true;
			}
			else
			{
				LOG(WARN, "unrecognized option {}", arg);
			}
		}
		else
		{
			fs::path arg_path = fs::absolute(arg);
			if (fs::is_directory(arg_path))
			{
				for (auto &p : fs::recursive_directory_iterator(arg_path))
				{
					auto pp = fs::absolute(p.path());
					if (fs::is_regular_file(pp))
					{
						LOG(INFO, "Provider DLL at {}", pp.string());
						pool->add_provider(std::make_shared<Provider_DynamicallyLinkedLibrary>(pp.string()));
					}
				}
			}
			else if (fs::is_regular_file(arg_path))
			{
				LOG(INFO, "Provider DLL at {}", arg_path.string());
				pool->add_provider(std::make_shared<Provider_DynamicallyLinkedLibrary>(arg_path.string()));
			}
			else
			{
				LOG(WARN, "{} is not a regular file/folder, treated as a file", arg_path.string());
				pool->add_provider(std::make_shared<Provider_DynamicallyLinkedLibrary>(arg_path.string()));
			}
		}
	}
	pool->add_provider(std::make_shared<Provider_StaticallyLinkedLibrary>());

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

	if (sys_prefixes.size() == 0)
	{
		sys_prefixes.push_back(fs::current_path());
	}

	for (auto it = sys_prefixes.rbegin(); it != sys_prefixes.rend(); it++)
	{
		const auto &prefix = *it;

		ctx_load.sys_prefixes.push_back(prefix.string());
		LOG(INFO, "sysprefix at {}", prefix.string());
	}

	for (const auto &lib : sys_libraries)
	{
		bool found = false;
		for (auto it = sys_prefixes.rbegin(); it != sys_prefixes.rend(); it++)
		{
			const auto &prefix = *it;

			auto resolved = prefix / lib;
			if (fs::exists(resolved))
			{
				auto filename = resolved.string();
				LOG(INFO, "Target Library at {}", filename);
				if (load_elf(filename, ctx_load, coord) != 0)
				{
					LOG(CRITICAL, "{} load_elf failed", filename);
					return 1;
				}
				found = true;
				break;
			}
		}

		if (!found)
		{
			LOG(WARN, "{} does not exist", lib);
		}
	}

	for (const auto &velf : velfs)
	{
		if (fs::exists(velf))
		{
			LOG(INFO, "VELF at {}", velf.string());
			if (load_velf(velf.string(), ctx_load, coord) != 0)
			{
				LOG(CRITICAL, "{} load_velf failed", velf.string());
				return 2;
			}
			continue;
		}
		LOG(WARN, "{} does not exist", velf.string());
	}

	TLS::reset();
	return 0;
}
