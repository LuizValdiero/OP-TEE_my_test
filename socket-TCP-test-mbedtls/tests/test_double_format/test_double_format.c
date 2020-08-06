#include "../../src/utils/double_format_handler.h"

#include <stdlib.h>
#include <string.h>

int main()
{
    char buffer[100];
    double my_double;;

    my_double = 15.03;
    memset(buffer, 0, 100);
    snprintf_double(buffer, 100, my_double);
    printf("\n  . %s\n", buffer);

    my_double = -15.03;
    memset(buffer, 0, 100);
    snprintf_double(buffer, 100, my_double);
    printf("\n  . %s\n", buffer);

    my_double = 1002.1234;
    memset(buffer, 0, 100);
    snprintf_double(buffer, 100, my_double);
    printf("\n  . %s\n", buffer);

    my_double = 0.00001f;
    memset(buffer, 0, 100);
    snprintf_double(buffer, 100, my_double);
    printf("\n  . %s\n", buffer);


    return 0;
}
