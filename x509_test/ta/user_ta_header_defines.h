#ifndef USER_TA_HEADER_DEFINES_H
#define USER_TA_HEADER_DEFINES_H

/* To get the TA UUID definition */
#include <x509_test_ta.h>

#define TA_UUID				TA_X509_TEST_UUID

/*
 * TA properties: multi-instance TA, no specific attribute
 * TA_FLAG_EXEC_DDR is meaningless but mandated.
 */
#define TA_FLAGS			TA_FLAG_EXEC_DDR

/* Provisioned stack size */
// https://github.com/OP-TEE/optee_test/pull/279#pullrequestreview-122070464
#define TA_STACK_SIZE			(32 * 1024)

/* Provisioned heap size for TEE_Malloc() and friends */
#define TA_DATA_SIZE			(32 * 1024)

/* The gpd.ta.version property */
#define TA_VERSION	"1.0"

/* The gpd.ta.description property */
#define TA_DESCRIPTION	"X509_TEST"

#endif /* USER_TA_HEADER_DEFINES_H */