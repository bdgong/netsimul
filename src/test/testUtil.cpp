/*
 * Compile: (path = $NETSIMUL/src/test)
 *
 * :!g++ % ../Util.cpp -I../include -o testUtil
 * */
#include "Util.h"

int main()
{
    debug("Hi?\n");
    debug("Hi? %d\n", 7);
    debug("Hi? %d %d\n", 7, 17);
    return 0;
}

