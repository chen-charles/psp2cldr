#ifndef PSP2CLDR_PROVIDER_H
#define PSP2CLDR_PROVIDER_H

#include <cstdint>
#include <memory>
#include <string>
#include <unordered_map>
#include <vector>

#include <psp2cldr/arch.h>

static inline const char vita_imp_nid_export_name_pattern[]{"psp2cldr_imp_%08X_%08X_"};
static inline const char vita_imp_sym_export_name_pattern[]{"psp2cldr_imp_%s_"};

class InterruptContext;
class HandlerResult;
typedef std::shared_ptr<HandlerResult> (*provider_func_call)(InterruptContext *);

class Provider
{
public:
    Provider() {}
    virtual ~Provider() {}

public:
    virtual provider_func_call get(uint32_t libraryNID, uint32_t functionNID) const = 0;
    virtual provider_func_call get(const std::string &name) const = 0;
};

class Provider_DynamicallyLinkedLibrary : public Provider
{
public:
    Provider_DynamicallyLinkedLibrary(const std::string &name);
    virtual ~Provider_DynamicallyLinkedLibrary();

    virtual provider_func_call get(uint32_t libraryNID, uint32_t functionNID) const
    {
        char buf[4096];
        snprintf(buf, 4096, vita_imp_nid_export_name_pattern, libraryNID, functionNID);
        return (provider_func_call)get_impl(buf);
    }

    virtual provider_func_call get(const std::string &name) const
    {
        char buf[4096];
        snprintf(buf, 4096, vita_imp_sym_export_name_pattern, name.c_str());
        return (provider_func_call)get_impl(buf);
    }

protected:
    std::string m_name;
    void *m_handle = nullptr;
    virtual void *get_impl(const std::string &) const;
};

class Provider_StaticallyLinkedLibrary : public Provider_DynamicallyLinkedLibrary
{
public:
    Provider_StaticallyLinkedLibrary() : Provider_DynamicallyLinkedLibrary("") {}
    virtual ~Provider_StaticallyLinkedLibrary() { m_handle = nullptr; }
};

class Provider_DynamicallyLinkedLibrary_Query : public Provider_DynamicallyLinkedLibrary
{
public:
    Provider_DynamicallyLinkedLibrary_Query(const std::string &name) : Provider_DynamicallyLinkedLibrary(name) {}

    typedef provider_func_call (*nid_query_sig)(uint32_t, uint32_t);
    virtual provider_func_call get(uint32_t libraryNID, uint32_t functionNID) const
    {
        return ((nid_query_sig)Provider_DynamicallyLinkedLibrary::get_impl(nid_query))(libraryNID, functionNID);
    }

    typedef provider_func_call (*sym_query_sig)(const char *);
    virtual provider_func_call get(const std::string &name) const
    {
        return ((sym_query_sig)Provider_DynamicallyLinkedLibrary::get_impl(sym_query))(name.c_str());
    }

    virtual ~Provider_DynamicallyLinkedLibrary_Query(){};

protected:
    static inline const char nid_query[]{"query_nid"};
    static inline const char sym_query[]{"query_sym"};
};

class Provider_Pool : public Provider
{
public:
    Provider_Pool() : Provider() {}
    virtual ~Provider_Pool()
    {
        m_nid_cache.clear();
        m_sym_cache.clear();
        m_providers.clear();
    }

    void add_provider(std::shared_ptr<const Provider> provider)
    {
        m_providers.push_back(provider);
    }

    virtual provider_func_call get(uint32_t libraryNID, uint32_t functionNID) const
    {
        auto hash = nid_hash(libraryNID, functionNID);
        if (m_nid_cache.count(hash) != 0)
        {
            return m_nid_cache[hash].lock()->get(libraryNID, functionNID);
        }

        for (auto &provider : m_providers)
        {
            auto f = provider->get(libraryNID, functionNID);
            if (f)
            {
                m_nid_cache[hash] = provider;
                return f;
            }
        }
        return NULL;
    }

    virtual provider_func_call get(const std::string &name) const
    {
        if (m_sym_cache.count(name) != 0)
        {
            return m_sym_cache[name].lock()->get(name);
        }

        for (auto &provider : m_providers)
        {
            auto f = provider->get(name);
            if (f)
            {
                m_sym_cache[name] = provider;
                return f;
            }
        }
        return NULL;
    }

protected:
    mutable std::unordered_map<NIDHASH_t, std::weak_ptr<const Provider>> m_nid_cache;
    mutable std::unordered_map<std::string, std::weak_ptr<const Provider>> m_sym_cache;
    std::vector<std::shared_ptr<const Provider>> m_providers;
};
#endif
