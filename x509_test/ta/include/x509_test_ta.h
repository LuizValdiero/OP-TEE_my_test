#ifndef TA_X509_TEST_H
#define TA_X509_TEST_H


/*
 * This UUID is generated with uuidgen
 * the ITU-T UUID generator at http://www.itu.int/ITU-T/asn1/uuid.html
 */
#define TA_X509_TEST_UUID \
	{ 0xe32608fd, 0x4eed, 0x4fa4, \
		{ 0xa3, 0x97, 0x2c, 0xfc, 0x63, 0x2b, 0xf4, 0x90} }
	
/* The function IDs implemented in this TA */

/*
 * TA_X509_CMD
 * 			param[0] unused
 * 			param[1] unused
 * 			param[2] unused
 * 			param[3] unused
 */
#define TA_X509_CMD 0

/*
 * TA_X509_CMD2
 * 			param[0] (memref) output
 * 			param[1] unused
 * 			param[2] unused
 * 			param[3] unused
 */
#define TA_X509_CMD2 1
		
#endif /*TA_X509_TEST_H*/
