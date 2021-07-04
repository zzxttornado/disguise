/*
 * disg_svr.h
 *
 *  Created on: Feb 10, 2015
 *      Author: jeff_zheng
 */

#ifndef DISG_SVR_H_
#define DISG_SVR_H_


#define DISG_MAX_PORT	16384

#include <poll.h>
#include <time.h>

#define DISG_PKT_HDR_MAGIC_DATA		0xEF3A9E23
#define DISG_PKT_HDR_MAGIC_PING		0xEF3A9E24
#define DISG_PKT_HDR_MAGIC_PING_ACK		0xEF3A9E25
#define DISG_PKT_HDR_MAGIC_PING_BACK		0xEF3A9E26
#define DISG_UDP_RCV_BUF_SIZE	65536

#define DISG_PKT_FLAG_FRAG			1
#define DISG_PKT_FLAG_FRAG_END		2

#undef DISG_LZO_SUPPORT

#pragma pack(1)
typedef struct disg_pkt_hdr_s
{
	uint32_t magic;
	uint16_t crc;
	uint16_t pkt_id;
#ifdef DISG_LZO_SUPPORT
	uint8_t frag:7;
	uint8_t lzo:1;
#else
	uint8_t frag;
#endif
	uint8_t seq;
	uint16_t size;
}disg_pkt_hdr;

typedef struct disg_pkt_hdr_frag_s
{

	disg_pkt_hdr	hdr;
	uint8_t			lzobuf[DISG_UDP_RCV_BUF_SIZE*2];
}disg_pkt_frag;

typedef struct disg_pkt_frag_node_s
{
	struct disg_pkt_frag_node_s* p_next;
	uint32_t		data_size;
	uint32_t		age;
	disg_pkt_frag	pkt;
}disg_pkt_frag_node;

#pragma pack()

typedef struct disg_arg_s
{
	char*		device;
	char*		peer;
	char*		stats_path;
	int			base_port;
	int			udp_port_cnt;
	int			sctp_port;
	uint32_t	max_ping_fail;
	uint32_t	verbose;
	bool		sctp_port_enable;
	bool		extra_frag;
#ifdef DISG_LZO_SUPPORT
	bool		lzo;
#endif
}disg_arg;

typedef struct disg_conn_s
{
	struct disg_conn_s* p_next;
	uint16_t	port;
	int sock;
	struct sockaddr remote_addr;
	socklen_t	remote_addr_len;

	int	tx_fail_cnt;
	int ping_fail_cnt;
	int failed;

}disg_conn;

typedef disg_conn* disg_conn_ptr;

typedef struct disg_stats_s
{
	uint64_t	tun_rx;
	uint64_t	tun_tx;
	uint64_t	ip_rx;
	uint64_t	ping_rx;
	uint64_t	noise_rx;
	uint64_t	ip_tx;
	uint64_t	tun_rx_bytes;
	uint64_t	tun_tx_bytes;
	uint64_t	ip_rx_bytes;
	uint64_t	ip_tx_bytes;
	uint64_t	crc_error;
	uint64_t	gap;
	uint64_t	ooo;
	uint64_t	dup;
	uint32_t	frag_list_cnt;
}disg_stats;

typedef struct disg_svr_s
{
	disg_arg*	p_arg;
	uint16_t	port_base;
	uint16_t	port_cnt;
	uint16_t	curr_tx_cnt;
	int		peer_set;
	int		running;
	int		tun_fd;
	int		conn_id_udp_tx_curr;
	int		conn_id_udp_tx_backup;
//	int		udp_sock_arr[DISG_MAX_PORT+1];
//	uint16_t udp_port_arr[DISG_MAX_PORT+1];

	int		sctp_listen_sock;
	int		sctp_client_fail;
//	struct disg_conn_s sctp_client_conn;
	struct disg_conn_s* sctp_conn;
	uint32_t	conn_list_id_curr;
	disg_conn_ptr p_conn_list[DISG_MAX_PORT];
	disg_conn_ptr p_conn_list_by_sock[DISG_MAX_PORT];

	struct pollfd pollfd_arr[DISG_MAX_PORT+1];
	uint16_t	pollfd_cnt;
	uint16_t	pollfd_sctp_listen;
	uint16_t	pollfd_sctp_conn_base;

	uint8_t			decomp_buf[DISG_UDP_RCV_BUF_SIZE*2];
	char			tun_rcv_buf[DISG_UDP_RCV_BUF_SIZE];
	disg_pkt_frag rx_pkt;

	uint32_t curr_tx_seq;
	uint32_t curr_ping_seq;
	uint32_t last_pkt_id;

	disg_pkt_frag_node*	p_rx_pkt;
	disg_pkt_frag_node*	p_rx_frag;
	disg_pkt_frag tx_pkt;

	struct sockaddr_in peer_addr;
	socklen_t peer_addr_len;

	struct sockaddr_in recv_addr;
	socklen_t saddr_len;

	time_t		last_timer_sec;
	struct tm	time_tm;
	char		time_str[64];
	disg_stats	stats_old;
	disg_stats	stats;
	char		stats_file[512];
}disg_svr;

disg_svr* disg_svr_create(disg_arg* p_arg);
int disg_svr_run(disg_svr* p_svr);

extern int g_disg_verbose;

#define DISG_CALL_INIT(func, ...)	\
	do { \
		ret = func(__VA_ARGS__); \
		if(ret < 0 ) {	\
			fprintf(stderr, "Failed to call %s error %d %s\n", #func, errno, strerror(errno)); \
			goto ERR_RET; \
		} \
	}while(0)

#define DISG_CALL_CREATE(p_obj, func, ...)	\
	do { \
		p_obj = func(__VA_ARGS__); \
		if(p_obj == NULL ) {	\
			fprintf(stderr, "Failed to call %s error %d %s\n", #func, errno, strerror(errno)); \
			goto ERR_RET; \
		} \
	}while(0)


#endif /* DISG_SVR_H_ */
