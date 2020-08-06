#include <sys/time.h>
#include <time.h>
#include <stdio.h>


long int get_time_usec() {
    struct timeval timer_usec;
    long int timestamp_usec;
    
    if (!gettimeofday(&timer_usec, NULL)) {
        timestamp_usec = ((long int) timer_usec.tv_sec) * 1000000l + 
                            (long int) timer_usec.tv_usec;
    }
    else {
        timestamp_usec = -1;
    }
    return timestamp_usec;
}

time_t second_to_micro(time_t second) {
    return second * 1000000;
}
time_t micro_to_second(time_t micro) {
    return micro / 1000000;
}

void print_date_second(time_t second) {

    char* c_time_string = ctime(&second);

    if (c_time_string == NULL)
    {
        printf("Failure to convert the current time.\n");
        return;
    }
    printf("date: %s\n", c_time_string);
}