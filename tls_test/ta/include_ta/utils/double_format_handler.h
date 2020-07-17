#ifndef DOUBLE_FORMAT_HANDLER_H
#define DOUBLE_FORMAT_HANDLER_H

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>

//https://github.com/OP-TEE/optee_os/issues/3286
// %f or any other floating point format is not supported.

int get_integer_of_double(double my_double);
int snprintf_double(char * s, int max_size, double doub);

#endif // DOUBLE_FORMAT_HANDLER_H