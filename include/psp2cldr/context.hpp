#ifndef PSP2CLDR_CONTEXT_H
#define PSP2CLDR_CONTEXT_H

#include <functional>
#include <memory>
#include <mutex>
#include <shared_mutex>
#include <string>
#include <unordered_map>
#include <unordered_set>

#include <psp2cldr/arch.h>

class InterruptContext;
class HandlerResult
{
public:
    HandlerResult(uint32_t result) : m_result(result) {}
    virtual ~HandlerResult() {}

    uint32_t result() const { return m_result; }

protected:
    uint32_t m_result;
};

class HandlerContinuation : public HandlerResult, public std::enable_shared_from_this<HandlerContinuation>
{
public:
    HandlerContinuation(uint32_t result, uint32_t fault_addr) : HandlerResult(result), fault_addr(fault_addr) {}
    virtual ~HandlerContinuation() {}

    virtual std::shared_ptr<HandlerContinuation> then(std::function<std::shared_ptr<HandlerResult>(uint32_t, InterruptContext *)> cont, std::function<void(int err)> fail = {})
    {
        if (!is_cont_set)
        {
            m_cont = cont;
            m_fail = fail;
            is_cont_set = true;
        }
        else
        {
            // not a clean solution,  but it works ...
            auto contcont = m_cont;
            m_cont = [contcont, cont, fail](uint32_t result, InterruptContext *ctx)
            {
                auto out = contcont(result, ctx);
                auto casted = std::dynamic_pointer_cast<HandlerContinuation>(out);
                if (casted)
                    return std::dynamic_pointer_cast<HandlerResult>(casted->then(cont, fail));
                return out;
            };
        }

        return shared_from_this();
    }

    std::shared_ptr<HandlerResult> continue_(uint32_t r, InterruptContext *ctx)
    {
        return m_cont(r, ctx);
    }

    static std::shared_ptr<HandlerResult> _default_cont(uint32_t result, InterruptContext *)
    {
        // default action if then() is not called, do nothing and return success
        return std::make_shared<HandlerResult>(0);
    }

private:
    uint32_t fault_addr;
    std::function<std::shared_ptr<HandlerResult>(uint32_t, InterruptContext *)> m_cont{_default_cont};
    std::function<void(int err)> m_fail;
    bool is_cont_set = false;
};

typedef std::function<std::shared_ptr<HandlerResult>(NID_t libraryNID, NID_t functionNID, InterruptContext *p_ctx)> unimplemented_nid_handler;
typedef std::function<std::shared_ptr<HandlerResult>(std::string name, Elf32_Sym sym, InterruptContext *p_ctx)> unimplemented_sym_handler;

struct nid_stub
{
    NID_t libraryNID;
    NID_t functionNID;

    // return 0 on success, die otherwise...
    unimplemented_nid_handler func;
};

struct sym_stub
{
    std::string name;
    Elf32_Sym sym;

    // return 0 on success, die otherwise...
    unimplemented_sym_handler func;
};

#include <iomanip>
#include <sstream>

static inline std::string u32_str_repr(uint32_t val) // {:#010x}
{
    std::stringstream ss;
    ss << "0x" << std::setfill('0') << std::setw(8) << std::hex << std::right << val;
    return ss.str();
}

class import_stub_entry
{
public:
    import_stub_entry() { type = 0; }
    import_stub_entry(nid_stub &stub) : nid(stub) { type = 1; }
    import_stub_entry(sym_stub &stub) : sym(stub) { type = 2; }

    std::shared_ptr<HandlerResult> call(InterruptContext *ctx)
    {
        switch (type)
        {
        case 1:
            return nid.func(nid.libraryNID, nid.functionNID, ctx);
        case 2:
            return sym.func(sym.name, sym.sym, ctx);
        default:
            throw;
        }
    }

    std::string repr() const
    {
        switch (type)
        {
        case 1:
            return "nid library=" + u32_str_repr(nid.libraryNID) + " function=" + u32_str_repr(nid.functionNID);
        case 2:
            return "symbol \"" + sym.name + "\"";
        default:
            return "invalid";
        }
    }

    ~import_stub_entry() {}

public:
    int type;
    nid_stub nid;
    sym_stub sym;
};

class Provider;
class LoadContext
{
public:
    LoadContext(std::shared_ptr<Provider> external_provider) : m_ext_provider(external_provider) {}
    LoadContext() {}
    virtual ~LoadContext() { m_ext_provider = nullptr; }

public:
    // ELF/VELF dependency search paths
    std::vector<std::string> search_paths;

    // velf fullname provided to psp2cldr, kept for provider's reference
    std::string main_velf_fullname;

    std::unordered_map<NID_t, std::string> nid_to_filename;

public:
    // target routines to be called per thread
    std::vector<uint32_t> thread_init_routines;
    std::vector<uint32_t> thread_fini_routines; // should be called reversely

    // main thread fini routines, should be called prior to main thread's exit, reversely
    std::vector<uint32_t> mainthread_fini_routines;

public:
    /* loader context */
    std::shared_mutex unimplemented_targets_mutex;
    std::unordered_map<uint32_t, import_stub_entry> unimplemented_targets; // unresolved import location, import_stub_entry

    /* VELF specific */
    std::unordered_map<NID_t, std::unordered_set<NID_t>> nids_loaded;               // moduleNID, [funcNID, ...]
    std::unordered_map<NIDHASH_t, std::pair<bool, uint32_t>> nids_export_locations; // (moduleNID, funcNID), <isVariable, actual loaded location>

    /* ELF specific */
    std::unordered_map<std::string, std::pair<uint32_t, uint32_t>> libs_loaded;             // library_name, <load_base, load_sz>
    std::unordered_map<std::string, std::pair<uint32_t, uint32_t>> libs_exidx;              // unwind support: library_name, <exidx_la, exidx_sz>
    std::unordered_map<std::string, std::pair<Elf32_Sym, uint32_t>> libs_export_locations;  // symbol_name, <Sym, ptr_f>
    std::unordered_map<std::string, std::vector<uint32_t>> libs_preemptable_symbols;        // symbol_name, [prev_import_ptr_f, ...]
    virtual std::pair<std::string, uint32_t> try_resolve_location(uint32_t location) const; // <library_name, offset> or library_name == ""

public:
    std::shared_ptr<Provider> provider() { return m_ext_provider; }

protected:
    std::shared_ptr<Provider> m_ext_provider;
};

class ExecutionCoordinator;
class ExecutionThread;
class InterruptContext
{
public:
    InterruptContext(ExecutionCoordinator &coord, ExecutionThread &thread, LoadContext &load) : coord(coord), thread(thread), load(load) {}
    virtual ~InterruptContext() {}

    template <typename... Targs>
    std::shared_ptr<HandlerContinuation> handler_call_target_function(NIDHASH_t nid_hash, Targs &&...args)
    {
        return handler_call_target_function_unpack(0, nid_hash, args...);
    }

    template <typename... Targs>
    std::shared_ptr<HandlerContinuation> handler_call_target_function(std::string name, Targs &&...args)
    {
        return handler_call_target_function_unpack(0, name, args...);
    }

public:
    ExecutionCoordinator &coord;
    ExecutionThread &thread;
    LoadContext &load;

public:
    virtual std::shared_ptr<HandlerResult> install_forward_handler(std::string target);
    virtual std::string read_str(uint32_t p_cstr) const;
    virtual void panic(int code = 0);

protected:
    virtual std::shared_ptr<HandlerContinuation> handler_call_target_function_impl(NIDHASH_t nid_hash);
    virtual std::shared_ptr<HandlerContinuation> handler_call_target_function_impl(std::string name);

protected:
    virtual void set_function_call_parameter(int idx, uint32_t value);

    std::shared_ptr<HandlerContinuation> handler_call_target_function_unpack(int idx, NIDHASH_t nid_hash)
    {
        return handler_call_target_function_impl(nid_hash);
    }

    template <typename T>
    std::shared_ptr<HandlerContinuation> handler_call_target_function_unpack(int idx, NIDHASH_t nid_hash, T value)
    {
        set_function_call_parameter(idx, value);
        return handler_call_target_function_unpack(idx + 1, nid_hash);
    }

    template <typename T, typename... Targs>
    std::shared_ptr<HandlerContinuation> handler_call_target_function_unpack(int idx, NIDHASH_t nid_hash, T value, Targs &&...args)
    {
        set_function_call_parameter(idx, value);
        return handler_call_target_function_unpack(idx + 1, nid_hash, args...);
    }

    std::shared_ptr<HandlerContinuation> handler_call_target_function_unpack(int idx, std::string name)
    {
        return handler_call_target_function_impl(name);
    }

    template <typename T>
    std::shared_ptr<HandlerContinuation> handler_call_target_function_unpack(int idx, std::string name, T value)
    {
        set_function_call_parameter(idx, value);
        return handler_call_target_function_unpack(idx + 1, name);
    }

    template <typename T, typename... Targs>
    std::shared_ptr<HandlerContinuation> handler_call_target_function_unpack(int idx, std::string name, T value, Targs &&...args)
    {
        set_function_call_parameter(idx, value);
        return handler_call_target_function_unpack(idx + 1, name, args...);
    }
};

#endif
