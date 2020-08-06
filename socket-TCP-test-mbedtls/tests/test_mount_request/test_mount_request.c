#include "../../src/my_post.h"

#include "../../src/decrypt.h"

int main(int argc, char const *argv[])
{
    char buffer_out[512];
    memset(buffer_out, 0, 512);
    const char * hostname = "iot.lisha.ufsc.br";

    struct HttpHeader_t httpHeader = { \
        .method = POST, \
        .path = API_GET, \
        .content_type = JSON, \
        .hostname = hostname, \
        .content_length = 0};
    //*
    struct Serie serie = {17, 2224179556, 741868840, 679816441, \
                    25300, 0, 0, 1567021716000000, 1567028916000000};
    // */
    struct Credentials credentials = {"smartlisha", "", ""};

    int size = mount_request((char *) buffer_out, 512, &httpHeader, SERIE, &serie, &credentials);
    printf("\n---\n%s\n---\n", buffer_out);

    memset(buffer_out, 0, 512);
    char buffer_package[512];
    void * data_package = 0;


    create_package(&data_package, SERIE, (void*) &serie);
    
    printf("type package: %c\n", *((char*)data_package));
    printf("version: %x\n",((struct Serie *) (data_package+1))->version);
    struct Serie * serie_pointer = (struct Serie *) (data_package+1);

    printf("dev: %d\n", ( serie_pointer->x));

    series_print_json(buffer_out, 512, serie_pointer);
    printf("\n\nserie print json\n%s\n", buffer_out);

    memset(buffer_out, 0, 512);
    size = mount_request((char *) buffer_out, 512, &httpHeader, SERIE, serie_pointer, &credentials);
    printf("\n---\n%s\n---\n", buffer_out);

    free_package(data_package);
    return 0;
}