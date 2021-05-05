#include <psp2cldr/logger.hpp>
#include <psp2cldr/panic.hpp>

#ifdef _MSC_VER
#include <intrin.h>
#else
#include <signal.h>
#endif

auto panic_logger = spdlog::stderr_color_mt("psp2cldr panic");

void psp2cldr_panic(int code, PanicDumpable *dumpable)
{
    panic_logger->set_pattern("PANIC > %v");
    panic_logger->info("code={:#x}", code);
    panic_logger->info("(PanicDumpable*)={:#x}", (uintptr_t)dumpable);

    if (dumpable)
    {
        dumpable->panic_dump(panic_logger, code);
    }
#ifdef _MSC_VER
    __debugbreak();
#else
    raise(SIGTRAP);
#endif
    throw std::runtime_error("psp2cldr_panic called");
}

#include <psp2cldr/context.hpp>
#include <psp2cldr/coordinator_impl.hpp>
void InterruptContext::panic_dump_impl(std::shared_ptr<spdlog::logger> logger, int code)
{
    coord.panic_dump(logger, code);
    load.panic_dump(logger, code);
}

void LoadContext::panic_dump_impl(std::shared_ptr<spdlog::logger> logger, int code)
{
}
