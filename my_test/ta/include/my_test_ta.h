#ifndef TA_MY_TEST_H
#define TA_MY_TEST_H


/*
 * This UUID is generated with uuidgen
 * the ITU-T UUID generator at http://www.itu.int/ITU-T/asn1/uuid.html
 */
#define TA_MY_TEST_UUID \
   { 0x22f95932, 0xbc9a, 0x47de, \
       { 0xa8, 0x0a, 0x51, 0xed, 0xe5, 0xc4, 0x0f, 0x2f} }
	
/* The function IDs implemented in this TA */
#define TA_MY_TEST_CMD_INC_VALUE		0
#define TA_MY_TEST_CMD_DEC_VALUE		1
#define TA_MY_TEST_ENCRYPT128		2

#endif /*TA_MY_TEST_H*/
