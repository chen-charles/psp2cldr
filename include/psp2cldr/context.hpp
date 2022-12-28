/*
 * Copyright (C) 2021-2022 Jianye Chen
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

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
	HandlerResult(uint32_t result) : m_result(result)
	{}

	virtual ~HandlerResult()
	{}

	virtual uint32_t result() const
	{
		return m_result;
	}
	virtual const std::exception *exception() const
	{
		return nullptr;
	}

protected:
	uint32_t m_result;
};

class HandlerExceptionBaseException : public std::exception
{
public:
	virtual bool cleanup(InterruptContext *ctx) const = 0;
};

template <class ExceptionType, typename = typename std::enable_if<std::is_base_of<std::exception, ExceptionType>::value>::type>
class HandlerException : public HandlerResult
{
public:
	HandlerException(ExceptionType &&exception) : HandlerResult(1), m_excp(std::move(exception))
	{}
	virtual ~HandlerException()
	{}

	virtual const std::exception *exception() const override
	{
		return &m_excp;
	}

protected:
	ExceptionType m_excp;
};

class HandlerContinuation : public HandlerResult, public std::enable_shared_from_this<HandlerContinuation>
{
public:
	HandlerContinuation(uint32_t result) : HandlerResult(result)
	{}
	virtual ~HandlerContinuation()
	{}

	virtual std::shared_ptr<HandlerContinuation> then(std::function<std::shared_ptr<HandlerResult>(uint32_t, InterruptContext *)> cont,
													  std::function<void(int err)> fail = {})
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
			m_cont = [contcont, cont, fail](uint32_t result, InterruptContext *ctx) {
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
	enum class type_t : uint8_t
	{
		NONE = 0,
		NID,
		SYM,
	};

public:
	import_stub_entry() = default;
	import_stub_entry(const nid_stub &stub) : type(type_t::NID), nid(stub)
	{}

	import_stub_entry(const sym_stub &stub) : type(type_t::SYM), sym(stub)
	{}

	std::shared_ptr<HandlerResult> call(InterruptContext *ctx)
	{
		switch (type)
		{
		case type_t::NID:
			return nid.func(nid.libraryNID, nid.functionNID, ctx);
		case type_t::SYM:
			return sym.func(sym.name, sym.sym, ctx);
		default:
			throw;
		}
	}

	std::string repr() const
	{
		switch (type)
		{
		case type_t::NID:
			return "nid library=" + u32_str_repr(nid.libraryNID) + " function=" + u32_str_repr(nid.functionNID);
		case type_t::SYM:
			return "symbol \"" + sym.name + "\"";
		default:
			return "invalid";
		}
	}

	~import_stub_entry()
	{}

public:
	type_t type = type_t::NONE;
	nid_stub nid;
	sym_stub sym;
};

class Provider;
class LoadContext
{
public:
	LoadContext(std::shared_ptr<Provider> external_provider) : m_ext_provider(external_provider)
	{}
	LoadContext()
	{}
	virtual ~LoadContext()
	{
		m_ext_provider = nullptr;
	}

public:
	// --sysprefix, search paths
	std::vector<std::string> sys_prefixes;

	std::unordered_map<std::string, std::string> additional_options;

	std::unordered_map<NID_t, std::string> nid_to_filename;

public:
	// target routines to be called per thread
	std::vector<std::pair<uint32_t, std::string>> thread_init_routines;
	std::vector<std::pair<uint32_t, std::string>> thread_fini_routines; // should be called reversely

	// main thread fini routines, should be called prior to main thread's exit, reversely
	std::vector<uint32_t> mainthread_fini_routines;

public:
	/* loader context */
	std::shared_mutex unimplemented_targets_mutex;
	std::unordered_map<uint32_t, import_stub_entry> unimplemented_targets; // unresolved import location, import_stub_entry

	/* VELF specific */
	std::unordered_map<NID_t, std::unordered_set<NID_t>> nids_loaded;				// moduleNID, [funcNID, ...]
	std::unordered_map<NIDHASH_t, std::pair<bool, uint32_t>> nids_export_locations; // (moduleNID, funcNID), <isVariable, actual loaded location>

	/* ELF specific */
	std::unordered_map<std::string, std::pair<uint32_t, uint32_t>> libs_loaded;				// library_name, <load_base, load_sz>
	std::unordered_map<std::string, std::pair<uint32_t, uint32_t>> libs_exidx;				// unwind support: library_name, <exidx_la, exidx_sz>
	std::unordered_map<std::string, std::pair<Elf32_Sym, uint32_t>> libs_export_locations;	// symbol_name, <Sym, ptr_f>
	std::unordered_map<std::string, std::vector<uint32_t>> libs_preemptable_symbols;		// symbol_name, [prev_import_ptr_f, ...]
	virtual std::pair<std::string, uint32_t> try_resolve_location(uint32_t location) const; // <library_name, offset> or library_name == ""

public:
	std::shared_ptr<Provider> provider()
	{
		return m_ext_provider;
	}

protected:
	std::shared_ptr<Provider> m_ext_provider;
};

class ExecutionCoordinator;
class ExecutionThread;

extern void panic(ExecutionCoordinator *coord, ExecutionThread *thread = nullptr, LoadContext *load = nullptr, int code = 0, const char *msg = nullptr);

class InterruptContext
{
public:
	InterruptContext(ExecutionCoordinator &coord, ExecutionThread &thread, LoadContext &load) : coord(coord), thread(thread), load(load)
	{}
	virtual ~InterruptContext()
	{}

	template <typename... Targs>
	std::shared_ptr<HandlerContinuation> handler_call_target_function(NIDHASH_t nid_hash, Targs &&...args)
	{
		if (load.nids_export_locations.count(nid_hash) == 0)
			throw std::logic_error("attempted to call an unregistered target function");
		if (load.nids_export_locations[nid_hash].first)
			throw std::logic_error("attempted to call a variable");
		return handler_call_target_function_raw_unpack(std::to_string(nid_hash), 0, load.nids_export_locations[nid_hash].second, args...);
	}

	template <typename... Targs>
	std::shared_ptr<HandlerContinuation> handler_call_target_function(std::string name, Targs &&...args)
	{
		if (load.libs_export_locations.count(name) == 0)
			throw std::logic_error("attempted to call an unregistered target function");
		return handler_call_target_function_raw_unpack(name, 0, load.libs_export_locations[name].second, args...);
	}

	template <typename... Targs>
	std::shared_ptr<HandlerContinuation> handler_call_target_function_raw(uint32_t address, Targs &&...args)
	{
		return handler_call_target_function_raw_unpack("raw", 0, address, args...);
	}

public:
	ExecutionCoordinator &coord;
	ExecutionThread &thread;
	LoadContext &load;
	import_stub_entry entry;

	static std::recursive_mutex GLOBAL_PANIC_LOCK;

public:
	virtual std::shared_ptr<HandlerResult> install_forward_handler(std::string target);
	virtual std::string read_str(uint32_t p_cstr) const;
	virtual void panic(int code = 0, const char *msg = nullptr);

protected:
	virtual std::shared_ptr<HandlerContinuation> handler_call_target_function_raw_impl(std::string name, int n_params, uint32_t address);

protected:
	virtual void set_function_call_parameter(int idx, uint32_t value);

	std::shared_ptr<HandlerContinuation> handler_call_target_function_raw_unpack(std::string name, int idx, uint32_t address)
	{
		return handler_call_target_function_raw_impl(name, idx, address);
	}

	template <typename T>
	std::shared_ptr<HandlerContinuation> handler_call_target_function_raw_unpack(std::string name, int idx, uint32_t address, T value)
	{
		set_function_call_parameter(idx, value);
		return handler_call_target_function_raw_unpack(name, idx + 1, address);
	}

	template <typename T, typename... Targs>
	std::shared_ptr<HandlerContinuation> handler_call_target_function_raw_unpack(std::string name, int idx, uint32_t address, T value, Targs &&...args)
	{
		set_function_call_parameter(idx, value);
		return handler_call_target_function_raw_unpack(name, idx + 1, address, args...);
	}
};

#endif
