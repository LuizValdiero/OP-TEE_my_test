#include <utils/double_format_handler.h>

int get_integer_of_double(double my_double){
    return ((int) my_double);
}

int snprintf_double(char * s, int max_size, double doub) {
    long long integer_part = (long long) doub;
    double aux_double = (doub-integer_part);

    if (aux_double < 0.0001 && aux_double > -0.0001)
        return snprintf(s, max_size, "%lld.0000", integer_part);

    int num_zeros = 0;
    int i = 0;
    for (; i < 4; i++ ) {
        aux_double *= 10;
        if ((int) aux_double) break;
        num_zeros ++;
    }
    for (; i < 4; i++, aux_double *= 10);

    int float_part = abs(aux_double);
    
    if(num_zeros)
        return snprintf(s, max_size, "%lld.%0*d%d", integer_part, num_zeros, 0, float_part);
    return snprintf(s, max_size, "%lld.%d", integer_part, float_part);
}
