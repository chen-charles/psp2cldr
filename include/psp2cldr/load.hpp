#ifndef PSP2CLDR_LOAD_H
#define PSP2CLDR_LOAD_H
#include <string>

class LoadContext;
class ExecutionCoordinator;

int load_velf(const std::string &filename, LoadContext &ctx, ExecutionCoordinator &coordinator);
int load_elf(const std::string &filename, LoadContext &ctx, ExecutionCoordinator &coordinator);

#endif
