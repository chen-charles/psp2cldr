#ifndef PSP2CLDR_PANIC_H
#define PSP2CLDR_PANIC_H

#include <memory>

namespace spdlog
{
    class logger;
}

class PanicDumpable
{
public:
    void panic_dump(std::shared_ptr<spdlog::logger> logger, int code) { return panic_dump_impl(logger, code); }

protected:
    virtual void panic_dump_impl(std::shared_ptr<spdlog::logger> logger, int code = 0) {}
};

extern void psp2cldr_panic(int code = 0, PanicDumpable *dumpable = nullptr);

#endif
