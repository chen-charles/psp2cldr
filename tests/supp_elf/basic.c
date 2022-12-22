#include <stdio.h>

static int static_test = 5;
extern int basic_test_variable;

extern void __psp2cldr__internal_panic(const char *msg);

static void __attribute__((constructor)) startup()
{
	printf("Hello World\n");
	if (static_test - 5 + basic_test_variable - 42 != 0)
	{
		__psp2cldr__internal_panic("basic: test failed");
	}
}

static void __attribute__((destructor)) shutdown()
{}
