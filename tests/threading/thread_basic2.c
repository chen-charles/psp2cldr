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
    static const int NUM = 100;

    long stack_guard[NUM];
    for (int i = 0; i < NUM; i++)
    {
        stack_guard[i] = 0xdeadbeef;
    }

    SceUID result = sceKernelCreateThread("test", &thread_main, 0, 0x10000, 0, 0, NULL);
    for (int i = 0; i < NUM; i++)
    {
        if (stack_guard[i] != 0xdeadbeef)
        {
            sceClibPrintf("stack corrupted...\n");
            return 1;
        }
    }
    if (result >= 0)
    {
        uint32_t deadbeef = 0xDEADBEEF;
        if (sceKernelStartThread(result, 4, &deadbeef) >= 0)
        {
            for (int i = 0; i < NUM; i++)
            {
                if (stack_guard[i] != 0xdeadbeef)
                {
                    sceClibPrintf("stack corrupted...\n");
                    return 1;
                }
            }
            sceKernelDelayThread(1000000);
            for (int i = 0; i < NUM; i++)
            {
                if (stack_guard[i] != 0xdeadbeef)
                {
                    sceClibPrintf("stack corrupted...\n");
                    return 1;
                }
            }
            if (value != 42 || beef != deadbeef)
            {
                sceClibPrintf("dead at verification...\n");
                for (int i = 0; i < NUM; i++)
                {
                    if (stack_guard[i] != 0xdeadbeef)
                    {
                        sceClibPrintf("stack corrupted...\n");
                        return 1;
                    }
                }
                return 1;
            }
        }
        else
        {
            sceClibPrintf("dead at start...\n");
            for (int i = 0; i < NUM; i++)
            {
                if (stack_guard[i] != 0xdeadbeef)
                {
                    sceClibPrintf("stack corrupted...\n");
                    return 1;
                }
            }
            return 1;
        }
        sceKernelDeleteThread(result);
        for (int i = 0; i < NUM; i++)
        {
            if (stack_guard[i] != 0xdeadbeef)
            {
                sceClibPrintf("stack corrupted...\n");
                return 1;
            }
        }
        return 0;
    }
    else
    {
        sceClibPrintf("dead at creation...\n");
        for (int i = 0; i < NUM; i++)
        {
            if (stack_guard[i] != 0xdeadbeef)
            {
                sceClibPrintf("stack corrupted...\n");
                return 1;
            }
        }
        return 1;
    }

    return 1;
}
