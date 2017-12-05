#include "Util.h"
#include <cstdarg>

void log(const char *fmt, ...)
{
    va_list va;
    va_start(va, fmt);
    vfprintf(stdout, fmt, va);
    va_end(va);
}

void debug(const char *fmt, ...) 
{
#ifdef DEBUG
    printf("DEBUG: ");

    va_list va;
    va_start(va, fmt);

    vfprintf(stdout, fmt, va); 

    va_end(va);

#endif 
}

void error(const char *fmt, ...)
{
    printf("ERROR: ");
    va_list va;
    va_start(va, fmt);
    vfprintf(stderr, fmt, va);
    va_end(va);
}

