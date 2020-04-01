#ifndef USER_TA_HEADER_DEFINES_H
#define USER_TA_HEADER_DEFINES_H

#include <serial_test_ta.h>

#define TA_UUID				TA_SERIAL_TEST_UUID

#define TA_FLAGS			TA_FLAG_EXEC_DDR
#define TA_STACK_SIZE			(2 * 1024)
#define TA_DATA_SIZE			(32 * 1024)

#endif /*USER_TA_HEADER_DEFINES_H*/
