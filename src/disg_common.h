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
#define DISG_ERR(fmt, ...)	printf("[ERR]"fmt"\n", ## __VA_ARGS__)
#define DISG_ERRNO(fmt, ...)	printf("[ERR]"fmt " error %s(%d)\n", ## __VA_ARGS__, strerror(errno), errno)

#define DISG_LOG(fmt, ...) \
	do { \
		if (g_disg_verbose >= 1) \
			printf("[LOG]"fmt"\n", ## __VA_ARGS__); \
	} while(0)
#define DISG_INFO(fmt, ...) \
	do { \
		if (g_disg_verbose >= 2) \
			printf("[INF]"fmt"\n", ## __VA_ARGS__); \
	} while(0)
#define DISG_DBG(fmt, ...) \
	do { \
		if (g_disg_verbose >= 3) \
			printf("[DBG]"fmt"\n", ## __VA_ARGS__); \
	} while(0)

#define DISG_GET_SADDR_PORT(saddr)		(((struct sockaddr_in*)(&(saddr)))->sin_port)
#define DISG_GET_SADDR_ADDR(saddr)		(((struct sockaddr_in*)(&(saddr)))->sin_addr.s_addr)

#endif /* DISG_COMMON_H_ */
