/*
 * tun_dev.h
 *
 *  Created on: Jan 31, 2015
 *      Author: jeff_zheng
 */

#ifndef TUN_DEV_H_
#define TUN_DEV_H_


int disg_tun_open(char *dev);
int disg_tun_close(int fd, char *dev);
int disg_tun_write(int fd, char *buf, int len);
int disg_tun_read(int fd, char *buf, int len);


#endif /* TUN_DEV_H_ */
