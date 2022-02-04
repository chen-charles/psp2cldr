/*
 * Copyright (C) 2021-2022 Jianye Chen
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

#ifndef PSP2CLDR_LOAD_H
#define PSP2CLDR_LOAD_H

#include <string>

class LoadContext;
class ExecutionCoordinator;

int load_velf(const std::string &filename, LoadContext &ctx, ExecutionCoordinator &coordinator);
int load_elf(const std::string &filename, LoadContext &ctx, ExecutionCoordinator &coordinator);

#endif
