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
##### Variables
From the exporter's perspective, the location value (as in the export table) is the address to the data of the variable.  
From the importer's perspective, variables are function calls. Presumably that would return the location value(cannot be the value it self, nor can it be a pointer to the location, since the exporter didn't provide one).  

#### ELF
```cpp
#undef _fstat // WATCHOUT: _fstat might be defined somewhere else
DECLARE_VITA_IMP_SYM_EXPORT(_fstat)
```
##### Variables
From the exporter's perspective, it is a function call to a pointer to a pointer to data.  
From the importer's perspective, presumably it would be a function call to the exporter's exporting function.  

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
    // your implementation here
    return std::make_shared<HandlerResult>(0);
}
```

#### ELF
```cpp
#undef _fstat
DEFINE_VITA_IMP_SYM_EXPORT(_fstat)  // parameter (InterruptContext *ctx)
{
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
