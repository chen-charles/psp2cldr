#include <stdio.h>

static int static_test = 5;
extern int basic_test_variable;

static int __attribute__((constructor)) startup()
{
	printf("Hello World\n");
	return static_test - 5 + basic_test_variable - 42;
}

static int __attribute__((destructor)) shutdown()
{
	return 0;
}
