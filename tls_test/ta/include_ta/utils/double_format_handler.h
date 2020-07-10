#ifndef DOUBLE_FORMAT_HANDLER_H
#define DOUBLE_FORMAT_HANDLER_H

//https://github.com/OP-TEE/optee_os/issues/3286
// %f or any other floating point format is not supported.

int get_integer_of_double(double my_double);

int get_integer_of_double(double my_double){
    return ((int) my_double);
}

#endif // DOUBLE_FORMAT_HANDLER_H