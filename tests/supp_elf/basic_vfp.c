#include <stdio.h>

extern double psp2cldr_test_vfp(float a, double b, float c, double d, int e, int f);

extern void __psp2cldr__internal_panic(const char *msg);

static void __attribute__((constructor)) startup()
{
	float a, c;
	double b, d;
	int e, f;

	a = 0.9381024597085167;
	b = 0.153877109533743153877109533743;
	c = 0.5719319663280426;
	d = 0.88321545497066488832154549706648;
	e = 244812256;
	f = -2005947375;

	if (psp2cldr_test_vfp(a, b, c, d, e, f) != (e * f / a * b / c * d))
	{
		__psp2cldr__internal_panic("basic_vfp: test failed");
	}
}

static void __attribute__((destructor)) shutdown()
{
}
