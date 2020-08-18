#include <data_structure/serie.h>

int serie_mount(buffer_t * out, int *displacement, void * data) {
    serie_t * serie = (serie_t *) data;
    uint32_t size_serie = sizeof(serie_t);
    if (out->buffer_size < *displacement + size_serie)
        return CODE_ERROR_SHORT_BUFFER;
    
    memcpy(out->buffer + *displacement, serie, size_serie);
    *displacement += size_serie;
    return CODE_SUCCESS;
}

int serie_print_json(buffer_t * out, int *displacement, void * data) {
    serie_t * serie = (serie_t *) data;
    
    char * buffer = (char *) out->buffer + *displacement;
    int avaliable_size = out->buffer_size - *displacement;
    
    int size_print = snprintf(buffer, avaliable_size, \
        "\"series\": {\"version\": \"%d.%d\", " \
        "\"unit\": %u, \"x\": %d, \"y\": %d, \"z\": %d, " \
        "\"dev\": %u,  \"r\": %u, " \
        " \"t0\": %llu, \"t1\": %llu}", \
        get_version_high(serie->version), get_version_low(serie->version), \
        serie->unit, serie->x, serie->y, serie->z, \
        serie->dev, serie->r, \
        serie->t0, serie->t1);
    
    if(avaliable_size < size_print)
        return CODE_ERROR_SHORT_BUFFER;

    *displacement += size_print;

    return CODE_SUCCESS;
}

