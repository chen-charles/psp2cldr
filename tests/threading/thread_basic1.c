#include <vitasdk.h>

static int thread_main(SceSize argc, void *argv)
{
    return 0;
}

int do_create(const char *name, SceKernelThreadEntry entry, int prio, int stack, SceUInt attr, int affinity, SceKernelThreadOptParam *opt)
{
    SceUID result = sceKernelCreateThread(name, entry, prio, stack, attr, affinity, opt);
    if (result > 0)
    {
        sceKernelDeleteThread(result);
        return 0;
    }
    else
    {
        sceClibPrintf("dead...\n");
        return 1;
    }
}

int _start()
{
    char *arr[] = {"___xmain", "", "5s6d4a65sd465qw4e6q5w41e32as1d56wq4e9"};
    for (int i = 0; i < sizeof(arr) / sizeof(char *); i++)
    {
        int err = do_create(arr[i], &thread_main, 0, 0x1000, 0, 0, NULL);
        if (err)
            return err;
    }
    return 0;
}
