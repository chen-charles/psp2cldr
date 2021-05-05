#include <vitasdk.h>

uint32_t value = 0;
uint32_t beef = 0;
static int thread_main(SceSize argc, void *argv)
{
    value = 42;
    beef = *(uint32_t *)argv;
    return 0;
}

int _start()
{
    SceUID result = sceKernelCreateThread("test", &thread_main, 0, 0x10000, 0, 0, NULL);
    if (result >= 0)
    {
        uint32_t deadbeef = 0xDEADBEEF;
        if (sceKernelStartThread(result, 4, &deadbeef) >= 0)
        {
            sceKernelDelayThread(1000000);
            if (value != 42 || beef != deadbeef)
            {
                sceClibPrintf("dead at verification...\n");
                return 3;
            }
        }
        else
        {
            sceClibPrintf("dead at start...\n");
            return 2;
        }
        sceKernelDeleteThread(result);
    }
    else
    {
        sceClibPrintf("dead at creation...\n");
        return 1;
    }
    return 0;
}
