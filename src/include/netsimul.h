
#ifndef NETSIMUL_H_
#define NETSIMUL_H_

char __ch;
#define CLEAR() \
    while((__ch = getchar()) != '\n' && __ch != EOF)

/* default snap length (maximum bytes per packet to capture) */
#define SNAP_LEN 1518

#define SIZE_TOK_BUF 256

typedef struct tok {
    int v;              // value
    const char * s;     // string
} tok_t ;

#endif  // NETSIMUL_H_

