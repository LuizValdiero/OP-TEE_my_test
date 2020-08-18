#include <sys/time.h>
#include <stdio.h>


uint64_t get_time_usec() {
    struct timeval timer_usec;
    uint64_t timestamp_usec;
    
    if (!gettimeofday(&timer_usec, NULL)) {
        timestamp_usec = ((uint64_t) timer_usec.tv_sec) * 1000000 + 
                            (uint64_t) timer_usec.tv_usec;
    }
    else {
        timestamp_usec = 0;
    }
    return timestamp_usec;
}