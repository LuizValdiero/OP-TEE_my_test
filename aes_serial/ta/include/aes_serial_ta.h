#ifndef __AES_SERIAL_TA_H__
#define __AES_SERIAL_TA_H__

#define TA_AES_SERIAL_UUID \
	{ 0xd60c49d1, 0x87c4, 0x4507, { \
		0x92, 0x13, 0x4b, 0x13, 0x9d, 0xfa, 0x21, 0x81 } }

/*
 * TA_DECRYPT
 * param[0] (memref) input
 * param[1] (memref) output
 * param[2] unused
 * param[3] unused
 */
#define TA_DECRYPT		0

/*
 * TA_DECRYPT
 * param[0] (memref) input
 * param[1] (memref) output
 * param[2] unused
 * param[3] unused
 */
#define TA_ENCRYPT		1

#endif /* __AES_SERIAL_TA_H */
