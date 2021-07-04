/*
 * disg_common.h
 *
 *  Created on: Jan 30, 2015
 *      Author: jeff_zheng
 */

#ifndef DISG_COMMON_H_
#define DISG_COMMON_H_

#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <stdbool.h>

#include <sys/types.h>          /* See NOTES */
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <unistd.h>

#include <errno.h>
#include <string.h>
//		if(g_disg_verbose)


extern int g_disg_verbose;
#if 0
#define DISG_LOG_TIME	"[%s]"
#define DISG_LOG_TIME_ARG	, p_svr->time_str
#else
#define DISG_LOG_TIME
#define DISG_LOG_TIME_ARG
#endif
#define DISG_ERR(fmt, ...)	\
	do { \
		printf("[ERR]"fmt"\n", ## __VA_ARGS__); \
		fflush(stdout); \
	}while(0)

#define DISG_ERRNO(fmt, ...)	\
	do { \
		printf("[ERR]"fmt " error %s(%d)\n", ## __VA_ARGS__, strerror(errno), errno); \
		fflush(stdout); \
	}while(0)

#define DISG_LOG(fmt, ...) \
	do { \
		if (g_disg_verbose >= 1) {\
			printf("[LOG]"DISG_LOG_TIME fmt"\n" DISG_LOG_TIME_ARG , ## __VA_ARGS__); \
			fflush(stdout); \
		} \
	} while(0)
#define DISG_INFO(fmt, ...) \
	do { \
		if (g_disg_verbose >= 2) { \
			printf("[INF]"DISG_LOG_TIME fmt"\n" DISG_LOG_TIME_ARG , ## __VA_ARGS__); \
			fflush(stdout); \
		} \
	} while(0)
#define DISG_DBG(fmt, ...) \
	do { \
		if (g_disg_verbose >= 3) { \
			printf("[DBG]"fmt"\n", ## __VA_ARGS__); \
			fflush(stdout); \
		} \
	} while(0)

#define DISG_GET_SADDR_PORT(saddr)		(((struct sockaddr_in*)(&(saddr)))->sin_port)
#define DISG_GET_SADDR_ADDR(saddr)		(((struct sockaddr_in*)(&(saddr)))->sin_addr.s_addr)

static inline uint16_t disg_crc16(const uint8_t* data_p, uint8_t length){
    uint8_t x;
    uint16_t crc = 0xFFFF;

    while (length--){
        x = crc >> 8 ^ *data_p++;
        x ^= x>>4;
        crc = (crc << 8) ^ ((uint16_t)(x << 12)) ^ ((uint16_t)(x <<5)) ^ ((uint16_t)x);
    }
    return crc;
}

static inline void disg_hexdump (void *addr, int len) {
    int i, sp;
    uint8_t *pc = (uint8_t*)addr;

    // Process every byte in the data.
    for (i = 0; (i + 16)<= len; i+=16) {
        // Multiple of 16 means new line (with line offset).
    	printf("%04x: %02x %02x %02x %02x  %02x %02x %02x %02x  %02x %02x %02x %02x  %02x %02x %02x %02x\n",
    			i,
				pc[i+0], pc[i+1], pc[i+2], pc[i+3],
				pc[i+4], pc[i+5], pc[i+6], pc[i+7],
				pc[i+8], pc[i+9], pc[i+10], pc[i+11],
				pc[i+12], pc[i+13], pc[i+14], pc[i+15]);
    }
    printf("%04x:", i);
    sp=0;
    while(i<len)
    {
    	printf(" %02x", pc[i]);
    	if(sp %4 == 3)
    		printf(" ");
    	i++; sp++;
    }
    printf("\n");

}


#endif /* DISG_COMMON_H_ */
