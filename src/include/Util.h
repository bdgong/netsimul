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

#define SIZE_TOK_BUF 256

typedef struct tok {
    int v;              // value
    const char * s;     // string
} tok_t ;

extern const char * tok2str(const tok_t * tokp,
        const char * default_msg,
        int v);

class File 
{
    public:
        File(const char *filename) : file(NULL)
        {
            if ((file = fopen(filename, "w")) == NULL) {
                fprintf(stderr, "Cannot open file: %s, use standard output instead.\n", filename);
                file = stdout;
            }
            else {
                fprintf(stdout, "Open file: %s\n", filename);
            }
        }

        ~File() 
        {
            if (file != NULL)
                fclose(file);
        }

        FILE *get() const 
        {
            return file;
        }

    private:
        FILE *file;
};

#endif // UTIL_H_
