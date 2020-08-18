#include <utils/data_version_handler.h>

int get_version_high(uint8_t version) {
    return (version & 0xf0)>>4;
}

int get_version_low(uint8_t version) {
    return version & 0x0f;
}