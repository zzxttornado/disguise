/*
 * disg_lzo.h
 *
 *  Created on: Feb 11, 2015
 *      Author: jeff_zheng
 */

#ifndef DISG_LZO_H_
#define DISG_LZO_H_


int disg_lzo_init(void);
/*
 * Deinitialize compressor/decompressor.
 * Free the buffer.
 */

int diag_free_lzo();

/*
 * This functions _MUST_ consume all incoming bytes in one pass,
 * that's why we expand buffer dynamicly.
 */
int disg_comp_lzo(int len, char *in, char *out);
int disg_decomp_lzo(int len, char *in, char *out);
#endif /* DISG_LZO_H_ */
