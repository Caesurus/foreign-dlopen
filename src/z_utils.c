#include <stdlib.h>

void *z_memset(void *s, int c, size_t n)
{
	unsigned char *p = s, *e = p + n;
	while (p < e)
		*p++ = c;
	return s;
}

void *z_memcpy(void *dest, const void *src, size_t n)
{
	unsigned char *d = dest;
	const unsigned char *p = src, *e = p + n;
	while (p < e)
		*d++ = *p++;
	return dest;
}

char *z_strstr(const char *h, const char *n)
{
	if (!*n)
		return (char *)h;
	for (; *h; h++)
	{
		const char *p = h, *q = n;
		while (*p && *q && *p == *q)
		{
			p++;
			q++;
		}
		if (!*q)
			return (char *)h;
	}
	return NULL;
}

int z_strcmp(const char *a, const char *b)
{
	while (*a && (*a == *b))
	{
		a++;
		b++;
	}
	return (unsigned char)*a - (unsigned char)*b;
}
