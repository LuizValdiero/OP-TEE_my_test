#include <string.h>

#define HOSTNAME "iot.lisha.ufsc.br"

#define ROUTE_REQUEST "/api/get.php"

#define PORT 443
#define LEN_BUFFER 2048

#define METHOD_REQUEST "POST"

#define BODY_VERSION    "'1.1'"
#define BODY_UNIT       "2147483648"
#define BODY_DOMAIN     "'multicore'"

#define BODY_T0 "1563365878640000"
#define BODY_T1 "1563366002746000"

#define BODY_DEV_A "900"
#define BODY_DEV_B "1200"

#define BODY \
"[{" \
"    'series' : {" \
"        'version' : "BODY_VERSION \
"        'unit' : "BODY_UNIT \
"        'x' : 0" \
"        'y' : 0" \
"        'z' : 0" \
"        'r' : 0" \
"        't0' : "BODY_T0 \
"        't1' : "BODY_T1 \
"        'dev' : "BODY_DEV_A \
"        'workflow' : 0" \
"    }" \
"    'credentials' : {" \
"        'domain' : "BODY_DOMAIN"" \
"    }" \
"}" \
"{" \
"    'series' : {" \
"        'version' : "BODY_VERSION \
"        'unit' : "BODY_UNIT \
"        'x' : 0" \
"        'y' : 0" \
"        'z' : 0" \
"        'r' : 0" \
"        't0' : "BODY_T0 \
"        't1' : "BODY_T1 \
"        'dev' : "BODY_DEV_B \
"        'workflow' : 0" \
"    }" \
"    'credentials' : {" \
"        'domain' : "BODY_DOMAIN"" \
"    }" \
"}]"

#define BODY2 \
"{\"series\": {\"r\": 0, \"version\": \"1.1\", "\
"\"t0\": 1563365878640000, \"workflow\": 0,"\
" \"y\": 0, \"x\": 0, \"z\": 0, \"dev\": 903,"\
" \"unit\": 2147483648, \"t1\": 1563366002746000}, "\
"\"credentials\": {\"domain\": \"multicore\"}}"

int mount_request(char * buff) {
    return sprintf(buff, \
                "POST "ROUTE_REQUEST" HTTP/1.1\r\n" \
                "Host: "HOSTNAME"\r\n" \
                "Content-Length: %u\r\n" \
                "Content-Type: application/json\r\n\r\n" \
                BODY2, \
                strlen(BODY2));
}
