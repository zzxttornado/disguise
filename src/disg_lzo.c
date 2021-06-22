/*
 * disg_lzo.c
 *
 *  Created on: Feb 11, 2015
 *      Author: jeff_zheng
 */


/*
 VTun - Virtual Tunnel over TCP/IP network.

 Copyright (C) 1998-2008  Maxim Krasnyansky <max_mk@yahoo.com>

 VTun has been derived from VPPP package by Maxim Krasnyansky.

 This program is free software; you can redistribute it and/or modify
 it under the terms of the GNU General Public License as published by
 the Free Software Foundation; either version 2 of the License, or
 (at your option) any later version.

 This program is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 GNU General Public License for more details.
 */

/*
 * $Id: lfd_lzo.c,v 1.5.2.5 2012/07/09 01:01:08 mtbishop Exp $
 */

/* LZO compression module */

#include "disg_common.h"
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <syslog.h>


#include <lzo/lzoutil.h>
#include <lzo/lzo1x.h>

static lzo_voidp wmem;
//static int zbuf_size = 2048 * 2048 / 64 + 16 + 3;

/* Pointer to compress function */
int (*lzo1x_compress)(const lzo_byte *src, lzo_uint src_len, lzo_byte *dst,
		lzo_uint *dst_len, lzo_voidp wrkmem);
/*
 * Initialize compressor/decompressor.
 * Allocate the buffers.
 */

int disg_lzo_init(void)
{
	int zlevel = 1;
	lzo_uint mem;

	switch (zlevel)
	{
	case 9:
		lzo1x_compress = lzo1x_999_compress;
		mem = LZO1X_999_MEM_COMPRESS;
		break;
	default:
		lzo1x_compress = lzo1x_1_15_compress;
		mem = LZO1X_1_15_MEM_COMPRESS;
		break;
	}

	if (lzo_init() != LZO_E_OK)
	{
		DISG_ERR("Can't initialize compressor");
		return 1;
	}
	if (!(wmem = lzo_malloc(mem)))
	{
		DISG_ERR("Can't allocate buffer for the compressor");
		return 1;
	}

	DISG_DBG("LZO compression[level %d] initialized", zlevel);

	return 0;
}

/*
 * Deinitialize compressor/decompressor.
 * Free the buffer.
 */

int diag_free_lzo()
{
	lzo_free(wmem);
	wmem = NULL;
	return 0;
}

/*
 * This functions _MUST_ consume all incoming bytes in one pass,
 * that's why we expand buffer dynamicly.
 */
int disg_comp_lzo(int len, char *in, char *out)
{
	lzo_uint zlen = 0;
	int err;

	if ((err = lzo1x_compress((void *) in, len, (void*)out, &zlen, wmem)) != LZO_E_OK)
	{
		DISG_ERR("Compress error %d", err);
		return -1;
	}

	return zlen;
}

int disg_decomp_lzo(int len, char *in, char *out)
{
	lzo_uint zlen = 0;
	int err;

	if ((err = lzo1x_decompress((void *) in, len, (void*)out, &zlen, wmem))
			!= LZO_E_OK)
	{
		DISG_ERR("Decompress error %d", err);
		return -1;
	}

	return zlen;
}

