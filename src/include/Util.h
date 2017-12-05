#ifndef UTIL_H_
#define UTIL_H_

#include <cstdio>

#define DBG_PREFIX 1
#define DBG_NEWLINE (1 << 1)
#define DBG_DEFAULT (DBG_PREFIX | DBG_NEWLINE)
#define DBG_NONE 0

#define DEBUG 1

extern void log(const char *format,  ...);
extern void debug(const char *format,  ...);
extern void error(const char *format,  ...);

#endif // UTIL_H_
