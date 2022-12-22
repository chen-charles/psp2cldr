/*
 * Copyright (C) 2021-2022 Jianye Chen
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

#ifdef _WIN32
#include <Windows.h>
#else
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <dlfcn.h>
#endif

#include <psp2cldr/implementation/logger.hpp>
#include <psp2cldr/provider.hpp>

void *Provider_DynamicallyLinkedLibrary::get_impl(const std::string &name) const
{
	if (m_handle)
	{
#ifdef _WIN32
		return (void *)GetProcAddress((HMODULE)m_handle, name.c_str());
#else
		return (void *)dlsym(m_handle, name.c_str());
#endif
	}
	return NULL;
}

Provider_DynamicallyLinkedLibrary::Provider_DynamicallyLinkedLibrary(const std::string &name)
{
#ifdef _WIN32
	if (name.empty())
		m_handle = GetModuleHandle(NULL);
	else
		m_handle = LoadLibrary(name.c_str());

	if (!m_handle)
		LOG(WARN, "LoadLibrary failed");
#else
	if (name.empty())
		m_handle = dlopen(NULL, RTLD_NOW | RTLD_NOLOAD);
	else
		m_handle = dlopen(name.c_str(), RTLD_LAZY | RTLD_LOCAL);
#if 0
    {
        // all providers will be loaded into a new LM
        static bool lm_created = false;
        static Lmid_t lmid;
        if (!lm_created)
        {
            m_handle = dlmopen(LM_ID_NEWLM, name.c_str(), RTLD_LAZY | RTLD_LOCAL);
            if (m_handle)
            {
                if (dlinfo(m_handle, RTLD_DI_LMID, &lmid) != 0)
                {
                    LOG(WARN, "dlinfo failed: {}", dlerror());
                }
                else
                {
                    lm_created = true;
                }
            }
        }
        else
        {
            m_handle = dlmopen(lmid, name.c_str(), RTLD_LAZY | RTLD_LOCAL);
        }
    }
#endif

	if (!m_handle)
		LOG(WARN, "dl(m)open failed: {}", dlerror());
#endif
}

Provider_DynamicallyLinkedLibrary::~Provider_DynamicallyLinkedLibrary()
{
	if (m_handle)
	{
#ifdef _WIN32
		FreeLibrary((HMODULE)m_handle);
#else
		dlclose(m_handle);
#endif
		m_handle = nullptr;
	}
}
