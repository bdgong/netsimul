#include "Util.h"
#include <cstdarg>

File fileDebug("debug.txt");
FILE *debugOut = fileDebug.get();

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
    va_list va;
    va_start(va, fmt);
    vfprintf(debugOut, fmt, va); 
    va_end(va);
    fflush(debugOut);
#endif 
}

void debug(int flag, const char *fmt, ...) 
{
#ifdef DEBUG
    if (flag & DBG_PREFIX) 
        fprintf(debugOut, "DEBUG: ");
    va_list va;
    va_start(va, fmt);
    vfprintf(debugOut, fmt, va); 
    va_end(va);
    if (flag & DBG_NEWLINE) 
        fprintf(debugOut, "\n");
    fflush(debugOut);
#endif 
}

void error(const char *fmt, ...)
{
    fprintf(stderr, "ERROR: ");
    va_list va;
    va_start(va, fmt);
    vfprintf(stderr, fmt, va);
    va_end(va);
}

const char * tok2str(const tok_t * tokp,
        const char * default_msg,
        int v)
{

    static char buf[SIZE_TOK_BUF];

    if(tokp != NULL) {
        while(tokp->s != NULL) {
            if(tokp->v == v)
                return tokp->s;
            else 
                ++tokp;
        }
    }

    snprintf(buf, SIZE_TOK_BUF, "%s", default_msg);
    return (const char *)buf;
}

