#ifndef __SERIAL_TEST_H__
#define __SERIAL_TEST_H__

/* UUID of the trusted application */
#define TA_SERIAL_TEST_UUID \
		{ 0xcffc270b, 0x1094, 0x4742, \
			{ 0xb2, 0x7d, 0xa1, 0x9a, 0x76, 0xb4, 0x00, 0x19 } }
			
/*
 * TA_INVERT
 * param[0] (memref) input
 * param[1] (memref) output
 * param[2] unused
 * param[3] unused
 */
#define TA_INVERT		0

#endif /* __SERIAL_TEST_H__ */
