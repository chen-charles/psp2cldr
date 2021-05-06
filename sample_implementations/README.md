Getting Started on Provider Implementations
=====
## Basics

### Includes
There is a single include you will need in order to access the `psp2cldr` provided interface.  
```cpp
#include <psp2cldr/imp_provider.hpp>
```

### Declaring an export
#### VITA
```cpp
DECLARE_VITA_IMP_NID_EXPORT(88758561, 391B74B8, ksceDebugPrintf) // ksceDebugPrintf is an alias that can be called from within the provider module
```

#### ELF
```cpp
#undef _fstat // WATCHOUT: _fstat might be defined somewhere else
DECLARE_VITA_IMP_SYM_EXPORT(_fstat)
```

### Defining an export
You will be returning a `shared_ptr` to `HandlerResult`, its definition is included from `imp_provider`.  
A value of `0` indicates success, and thus the execution continues. Anything other than that will cause a `panic` and some information of target environment being dumped.  
It is worth noting that returning from the handler does not implicitly cause the subroutine on the target to return. You will need to explicitly indicate that with,
```cpp
ctx->thread[RegisterAccessProxy::Register::PC]->w(ctx->thread[RegisterAccessProxy::Register::LR]->r());
```
#### VITA
```cpp
// note: variables are actually exported as a function call that returns
DEFINE_VITA_IMP_NID_EXPORT(88758561, 391B74B8)  // parameter (InterruptContext *ctx)
{
    DECLARE_VITA_IMP_TYPE(FUNCTION); // required, see "Notes on Variables"
    // your implementation here
    return std::make_shared<HandlerResult>(0);
}
```

#### ELF
```cpp
#undef _fstat
DEFINE_VITA_IMP_SYM_EXPORT(_fstat)  // parameter (InterruptContext *ctx)
{
    DECLARE_VITA_IMP_TYPE(FUNCTION); // required, see "Notes on Variables"
    // your implementation here
    return std::make_shared<HandlerResult>(0);
}
```

### Calling each other
**Re-entry is allowed**, i.e., a function `B` called by `A` may invoke `A` again.  

#### Calling an export inside the target environment
You can, with caution, to call functions that are loaded inside the target environment.  
A good example of this is to call a C library function.  
Suppose you are writing sceClibMemset with `newlib` already loaded into the target environment, 
```cpp
DECLARE_VITA_IMP_NID_EXPORT(F9C9C52F, 632980D7, sceClibMemset)
DEFINE_VITA_IMP_NID_EXPORT(F9C9C52F, 632980D7)
{
    DECLARE_VITA_IMP_TYPE(FUNCTION); // required, see "Notes on Variables"

    uint32_t dst = ctx->thread[RegisterAccessProxy::Register::R0]->r();
    uint32_t ch = ctx->thread[RegisterAccessProxy::Register::R1]->r();
    uint32_t len = ctx->thread[RegisterAccessProxy::Register::R2]->r();
    
    // you must return the continuation call instead of waiting for its completion
    return ctx->handler_call_target_function("memset", dst, ch, len)
        ->then([=](uint32_t result, InterruptContext *ctx) {
            ctx->thread[RegisterAccessProxy::Register::PC]->w(ctx->thread[RegisterAccessProxy::Register::LR]->r());
            return std::make_shared<HandlerResult>(0);
        });
}
```
In the `memset` case, it is a simple forward. You can replace `sceClibMemset`'s stub directly. 
```cpp
// the handler will only be executed once, the next time it directly goes to memset
VITA_IMP_NID_FORWARD_SYM(F9C9C52F, 632980D7, "memset")
```
You may also chain the continuations if you need to make multiple calls to the target environment,  
```cpp
DECLARE_VITA_IMP_NID_EXPORT(88758561, 391B74B7, ksceDebugPrintf)
DEFINE_VITA_IMP_NID_EXPORT(88758561, 391B74B7)
{
    DECLARE_VITA_IMP_TYPE(FUNCTION); // required, see "Notes on Variables"

    // 1st entry
    uint32_t r0 = ctx->thread[RegisterAccessProxy::Register::R0]->r();
    return ctx->handler_call_target_function("strlen", r0)
        ->then([=](uint32_t result, InterruptContext *ctx) {
            // 2nd entry: strlen returned
            return ctx->handler_call_target_function("printf", r0)->then([=](uint32_t result, InterruptContext *ctx) {
                // 3rd entry: printf returned
                ctx->coord.proxy().w<uint8_t>(r0, '\n');    // flush, incorrect as it's writing to const char*
                ctx->coord.proxy().w<uint8_t>(r0 + 1, 0);
                
                // if you do not return a continuation here, 4th entry's handler will never be called (it's discarded right away)
                return ctx->handler_call_target_function("printf", r0); 
            });
        })
        ->then([=](uint32_t result, InterruptContext *ctx) {
            // 4th entry: printf returned
            ctx->thread[RegisterAccessProxy::Register::PC]->w(ctx->thread[RegisterAccessProxy::Register::LR]->r());
            return std::make_shared<HandlerResult>(0);
        });
    // as illustrated, you can chain the continuations in a way you prefer, or even mix-and-matching. 
}
```

#### Calling an export inside another provider module
Intermodular calls are similar to how they are done from `psp2cldr`,  
```cpp
DECLARE_VITA_IMP_NID_EXPORT(88758561, 391B74B7, ksceDebugPrintf)
DEFINE_VITA_IMP_NID_EXPORT(88758561, 391B74B7)
{
    DECLARE_VITA_IMP_TYPE(FUNCTION); // required, see "Notes on Variables"
    
    provider_func_call p_func;

    p_func = ctx->load.provider()->get("symbol_name");
    if (p_func)
    {
        p_func(ctx);
    }

    p_func = ctx->load.provider()->get(nid_hash(0x11111111, 0x22222222));
    if (p_func)
    {
        p_func(ctx);
    }

    return std::make_shared<HandlerResult>(0);
}
```

#### Calling an export inside this provider module
```cpp
DECLARE_VITA_IMP_NID_EXPORT(88758561, 391B74B7, ksceDebugPrintf)
// its definition needs to be linked to this provider module

DECLARE_VITA_IMP_NID_EXPORT(F9C9C52F, 632980D7, sceClibMemset)
DEFINE_VITA_IMP_NID_EXPORT(F9C9C52F, 632980D7)
{
    return ksceDebugPrintf(ctx);
}
```

### Compilation
The provider module needs to be compiled as a shared library for the **HOST** platform. Please see `sample_implementations/`.  
It is recommended to use `-fvisibility=hidden` with `GNU Tools`, or equivalent flags on other compilers, to avoid exporting unnecessary symbols.  

### Notes on Variables
#### ELF
Suppose `rel.r_offset` has a value of `0xABCD`, which once loaded, is translated to `0xAAAAAAAA`, then,  
 * for variables: `[0xAAAAAAAA]` is a pointer to the imported variable  
 * for functions: `[0xAAAAAAAA]` is your new PC  
  
For stubbing, this means we need a level of indirection for functions, but we must not do that for variables.  
  
ELF does not differentiate between variables and functions, i.e., the importer has no idea if a symbol is a variable or a function based solely on the dynamic section.  You may argue that `R_*_GLOB_DAT` indicates a variable while `R_*_JUMP_SLOT` indicates a function, however, these two relocation types can usually interchange.  
  
To mitigate this issue, all exports are required to respond to a *poke*,  
```cpp
DEFINE_VITA_IMP_SYM_EXPORT(test_variable)
{
    DECLARE_VITA_IMP_TYPE(VARIABLE); // if (!ctx) return an indication that this is a VARIABLE
    // your implementation here, this handler is called each time a module/library imports this variable
    // _p_data is a pointer to the variable
    ctx->coord.proxy().w<uint32_t>(ctx->thread[RegisterAccessProxy::Register::PC]->r(), _p_data);
    TARGET_RETURN(0);
    HANDLER_RETURN(0);
}
```

#### VITA
Basically identical to ELF, except for a provided function stub that returns `-1` for each imported function.  
