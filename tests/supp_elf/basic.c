#include <stdio.h>

static int static_test = 5;

static int __attribute__((constructor))
startup()
{
    printf("Hello World\n");
    return static_test - 5;
}

static int __attribute__((destructor))
shutdown()
{
    return 0;
}
