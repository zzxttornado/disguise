/*
 * disg_svr.c
 *
 *  Created on: Jan 30, 2015
 *      Author: jeff_zheng
 */

#include "disg_common.h"
#include <poll.h>
#include <netdb.h>
#include "disg_tun_dev.h"
#include "disg_svr.h"
#include "disg_lzo.h"
#if 0
#include <netinet/sctp.h>
#endif
#include <time.h>
#include <pthread.h>
#include <inttypes.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#if 0
#define DISG_FRAG_DBG(p_node, fmt, ...) \
	do { \
		DISG_DBG("Frag %16lX CurrRX %16lX CurrFragHead %16lX %08x FLG %u seq %u size %4u |"fmt"\n", \
			(uintptr_t)(p_node), (uintptr_t)p_svr->p_rx_pkt, (uintptr_t)p_svr->p_rx_frag, \
				p_node->pkt.hdr.pkt_id, p_node->pkt.hdr.frag, p_node->pkt.hdr.seq, \
					p_node->pkt.hdr.size, ## __VA_ARGS__); \
	}while(0)
#else
#define DISG_FRAG_DBG(...)
#endif


#define DIAG_BITS_SWAP(val)			((((val) & 0xf0u) >> 4) | (((val) & 0xfu)<<4))

void disg_data_reverse_in_place(void* p_mem, int32_t data_size)
{
	uint8_t *mem = p_mem;
	int middle =(data_size)>>1;
	int start = 0;
	int end = data_size -1;
	uint8_t swap;

	while(start < middle)
	{
		swap = mem[start];
		mem[start] = DIAG_BITS_SWAP(mem[end]);
		mem[end] = DIAG_BITS_SWAP(swap);

		start ++;
		end--;
	}
}


disg_conn* disg_svr_conn_add_new(disg_svr* p_svr, int sock, struct sockaddr* p_sockaddr, int slen)
{
	disg_conn* p_conn;

	DISG_CALL_CREATE(p_conn, malloc, sizeof(*p_conn));
	memset(p_conn, 0, sizeof(*p_conn));
	if(p_sockaddr)
	{
		memcpy(&p_conn->remote_addr, p_sockaddr, slen);
		p_conn->remote_addr_len =  slen;
	}
	p_conn->sock = sock;
	p_conn->port = ntohs(((struct sockaddr_in*)p_sockaddr)->sin_port);

	p_svr->p_conn_list[p_svr->conn_list_id_curr] = p_conn;
	p_svr->p_conn_list_by_sock[sock] = p_conn;
	p_svr->conn_list_id_curr ++;
	p_svr->pollfd_arr[p_svr->pollfd_cnt].fd = p_conn->sock;
	p_svr->pollfd_cnt ++;
	return p_conn;
ERR_RET:
	return NULL;
}

int disg_svr_conn_remove(disg_svr* p_svr, disg_conn* p_conn)
{
	uint32_t loop, loop_max;
	loop_max = p_svr->pollfd_cnt - p_svr->pollfd_sctp_conn_base;

	p_svr->p_conn_list_by_sock[p_conn->sock] = NULL;
	for(loop = 0; loop < loop_max; loop++)
	{
		if(p_svr->p_conn_list[loop] == p_conn)
		{
			p_svr->p_conn_list[loop] = NULL;
			p_svr->pollfd_arr[loop+p_svr->pollfd_sctp_conn_base].fd = -1;
			break;
		}
	}
	if(loop == loop_max)
	{
		DISG_ERR("Connection not found for removal");
		return -1;
	}

	//shift the rest up
	while((loop+1) < loop_max)
	{
		p_svr->p_conn_list[loop] = p_svr->p_conn_list[loop+1];
		p_svr->pollfd_arr[loop+p_svr->pollfd_sctp_conn_base].fd = p_svr->pollfd_arr[loop+p_svr->pollfd_sctp_conn_base+1].fd;
	}
	p_svr->conn_list_id_curr --;
	p_svr->pollfd_cnt --;
	return 0;
}

int disg_svr_conn_remove_other(disg_svr* p_svr, disg_conn* p_keep)
{
	uint32_t loop, loop_max;
	loop_max = p_svr->pollfd_cnt - p_svr->pollfd_sctp_conn_base;

	for(loop = 0; loop < loop_max; loop++)
	{
		close(p_svr->p_conn_list[loop]->sock);
		free(p_svr->p_conn_list[loop]);
		p_svr->p_conn_list[loop] = NULL;
		p_svr->pollfd_arr[loop+p_svr->pollfd_sctp_conn_base].fd = -1;
	}

	p_svr->p_conn_list[0] = p_keep;
	p_svr->pollfd_arr[loop+p_svr->pollfd_sctp_conn_base].fd = p_keep->sock;
	p_svr->pollfd_cnt = p_svr->pollfd_sctp_conn_base + 1;

	return 0;
}

int disg_sock_create(disg_svr* p_svr, uint16_t port)
{
	struct sockaddr_in saddr;
	int s, opt;
	socklen_t opt_len;
	if ((s = socket(AF_INET, SOCK_DGRAM, 0)) == -1)
	{
		DISG_ERRNO("Can't create socket");
		return -1;
	}

	opt = 1;
	if(0!=setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)))
	{
		DISG_ERRNO("Can't setsockopt SO_REUSEADDR");
	}
	opt_len = sizeof(opt);
	if(getsockopt(s, SOL_SOCKET, SO_SNDBUF, &opt, &opt_len)==0)
	{
		DISG_DBG("Socket send buffer was %u", opt);
	}

	opt=1024*256;
	if(0!=setsockopt(s, SOL_SOCKET, SO_SNDBUF, &opt, sizeof(opt)))
	{
		DISG_ERRNO("Can't setsockopt SO_SNDBUF");
	}
	opt_len = sizeof(opt);
	if(getsockopt(s, SOL_SOCKET, SO_SNDBUF, &opt, &opt_len)==0)
	{
		DISG_DBG("Socket send buffer is %u", opt);
	}
	opt=1024*256;
	if(0!=setsockopt(s, SOL_SOCKET, SO_RCVBUF, &opt, sizeof(opt)))
	{
		DISG_ERRNO("Can't setsockopt SO_RCVBUF");
	}
	/* Set local address and port */
	saddr.sin_family = AF_INET;
	saddr.sin_addr.s_addr = INADDR_ANY;
	saddr.sin_port = htons(port);
	if (bind(s, (struct sockaddr *) &saddr, sizeof(saddr)))
	{
		DISG_ERRNO("Can't bind to the socket");
		return -1;
	}
	return s;
}


disg_svr g_disg_svr;


int disg_svr_process_send_udp(disg_svr* p_svr, disg_conn* p_conn, void* payload, int payload_size)
{
	int ret;
	struct sockaddr_in peer_addr = p_svr->peer_addr;
	peer_addr.sin_port = DISG_GET_SADDR_PORT(p_conn->remote_addr);

	ret = sendto(p_conn->sock, payload, payload_size, 0,
			(struct sockaddr*)&peer_addr, sizeof(peer_addr));
	if(ret!=payload_size)
	{
		DISG_ERRNO("Failed to write to sock %d return %d requested %d, port %5u",
				p_conn->sock,
					 ret, payload_size, p_conn->port);
	}
	else
	{
		p_svr->stats.ip_tx ++;
		p_svr->stats.ip_tx_bytes += payload_size;
	}

	return 0;
}

int disg_svr_sctp_client_connect(disg_svr* p_svr)
{
#if 0
	int ret;
	int sock = -1;
//	struct sockaddr saddr;
//	socklen_t slen = sizeof(struct sockaddr);

	DISG_CALL_INIT(socket, AF_INET, SOCK_STREAM, IPPROTO_SCTP);

	sock = ret;

	p_svr->peer_addr.sin_port = htons(p_svr->p_arg->sctp_port);
	DISG_CALL_INIT(connect, sock, (struct sockaddr*)(&p_svr->peer_addr), sizeof(p_svr->peer_addr));

	DISG_LOG("Connected to peer");
	disg_svr_conn_add_new(p_svr, sock, (struct sockaddr*)&p_svr->peer_addr, sizeof(p_svr->peer_addr));
//	p_svr->sctp_client_conn.sock = sock;
	return 0;

ERR_RET:
	if(sock != -1)
		close(sock);
	return -1;
#else
	return 0;
#endif
}

void* disg_svr_sctp_client_conn_thread(void* p_arg)
{
	disg_svr* p_svr = p_arg;
	p_svr->sctp_conn = NULL;
	while(1)
	{
		if(p_svr->sctp_conn == NULL)
		{
			if(0!=disg_svr_sctp_client_connect(p_svr))
			{
				continue;
			}
//			p_svr->sctp_client_conn.fail_cnt = 0;
//			p_svr->sctp_conn = &p_svr->sctp_client_conn;
//			p_conn = p_svr->sctp_conn;
//			p_svr->p_conn_list[p_conn->sock] = &p_svr->sctp_client_conn;
//			p_svr->pollfd_arr[p_svr->pollfd_sctp_conn_base].fd = p_svr->sctp_conn->sock;
//			p_svr->pollfd_cnt++;
		}
		else
		{
			struct timespec req = {0,10000000}; //10ms
			nanosleep(&req, NULL);
		}
	}
}

void disg_svr_close_sctp_conn(disg_svr* p_svr, disg_conn* p_conn)
{
	if(p_svr->p_arg->peer == NULL)
	{//server
		disg_svr_conn_remove(p_svr, p_conn);
		close(p_conn->sock);
		if(p_svr->sctp_conn == p_conn)
			p_svr->sctp_conn = NULL;
		free((void*)(p_conn));
	}
	else
	{//client
		p_svr->pollfd_cnt--;
		p_svr->pollfd_arr[p_svr->pollfd_cnt].fd = -1;
		close(p_conn->sock);
		p_svr->sctp_conn = NULL;
	}

}

int disg_svr_process_send_sctp(disg_svr* p_svr, int data_size)
{
#if 0
	int ret = 0;

	if(p_svr->sctp_conn)
	{
		ret = sctp_sendmsg(p_svr->sctp_conn->sock, &p_svr->tx_pkt, data_size+ sizeof(disg_pkt_hdr), NULL, 0, 0, 0, 0, 0, 0 );
		if(ret<0)
		{
			DISG_ERR("Failed to send sctp message, size %"PRIuPTR", err %d %s", data_size + sizeof(disg_pkt_hdr), errno, strerror(errno));
			p_svr->sctp_conn->tx_fail_cnt ++;
			if(p_svr->sctp_conn->tx_fail_cnt > 32)
			{
				disg_svr_close_sctp_conn(p_svr, p_svr->sctp_conn);
			}
		}
		else
			p_svr->sctp_conn->tx_fail_cnt = 0;
	}
	else
	{
		DISG_ERR("no availble sctp conn to send %"PRIuPTR" bytes", data_size + sizeof(disg_pkt_hdr));
	}

	return 0;
#else
	return 0;
#endif
}

#define DISG_SEG_SIZE		1412
#define DISG_SEG_COMP_SIZE	(DISG_SEG_SIZE - sizeof(disg_pkt_hdr))

int disg_svr_send_msg_udp(disg_svr* p_svr, disg_conn* p_conn, int data_size)
{
	if(data_size <= DISG_SEG_COMP_SIZE)
	{
		disg_svr_process_send_udp(p_svr, p_conn, &p_svr->tx_pkt, data_size+ sizeof(disg_pkt_hdr));
	}
	else
	{
		int comp_total_left_size = data_size;
		int comp_off = 0;
		int curr_comp_size;
		int pkt_seq = 0;
		p_svr->tx_pkt.hdr.frag = DISG_PKT_FLAG_FRAG;
		p_svr->tx_pkt.hdr.pkt_id = htons(p_svr->curr_tx_seq);

		while(comp_total_left_size)
		{
			curr_comp_size = DISG_SEG_COMP_SIZE;
			if(curr_comp_size > comp_total_left_size)
			{//last seg, or no seg
				p_svr->tx_pkt.hdr.frag = DISG_PKT_FLAG_FRAG_END;
				curr_comp_size = comp_total_left_size;
			}
			else
			{//need frag, let's see if we can fit in two
				if(comp_total_left_size < (DISG_SEG_COMP_SIZE*2))
				{//we can fit in two frag, let's devide in half
	
					curr_comp_size = ((comp_total_left_size/2)+0x80)&0xFFFFFFE0U;
				}
			}
			if(comp_off)
			{
				memcpy(p_svr->tx_pkt.lzobuf, p_svr->tx_pkt.lzobuf + comp_off, curr_comp_size);
			}
			p_svr->tx_pkt.hdr.seq = pkt_seq++;
			p_svr->tx_pkt.hdr.size = htons(curr_comp_size);
			disg_svr_process_send_udp(p_svr, p_conn, &p_svr->tx_pkt, curr_comp_size + sizeof(disg_pkt_hdr));
			comp_total_left_size -= curr_comp_size;

			if(p_svr->p_arg->extra_frag)
			{
				//send the last segment twice, this reduces gap,
				if(comp_total_left_size == 0)
					disg_svr_process_send_udp(p_svr, p_conn, &p_svr->tx_pkt, curr_comp_size + sizeof(disg_pkt_hdr));
			}

			comp_off += curr_comp_size;
		}
	}

	return 0;
}


void disg_svr_send_ping(disg_svr* p_svr, disg_conn* p_conn, bool send_ack, bool is_backup)
{
	if(send_ack)
		p_svr->tx_pkt.hdr.magic = htonl(DISG_PKT_HDR_MAGIC_PING_ACK);
	else
	{
		if(is_backup)
			p_svr->tx_pkt.hdr.magic = htonl(DISG_PKT_HDR_MAGIC_PING_BACK);
		else
			p_svr->tx_pkt.hdr.magic = htonl(DISG_PKT_HDR_MAGIC_PING);
	}
	p_svr->tx_pkt.hdr.frag = 0;
	p_svr->curr_ping_seq ++;
	p_svr->tx_pkt.hdr.seq = 0;
	p_svr->tx_pkt.hdr.pkt_id = htons(p_svr->curr_ping_seq);
	p_svr->tx_pkt.hdr.size = 20;

	DISG_INFO("%s Send %s to %08x.%5u, current fail %u",
			is_backup ? "BACK" :"MAIN",
			send_ack ? "PING_ACK" : "PING",
			DISG_GET_SADDR_ADDR(p_svr->peer_addr),
			p_conn->port, p_conn->ping_fail_cnt);
	disg_svr_process_send_udp(p_svr, p_conn, &p_svr->tx_pkt, sizeof(disg_pkt_hdr)+20);

}

int disg_svr_process_tun_recv_data(disg_svr* p_svr)
{
	char* p_rcv_buf = p_svr->tun_rcv_buf;
	int data_size = DISG_UDP_RCV_BUF_SIZE;
	uint16_t crc;

	data_size = read(p_svr->tun_fd, p_rcv_buf, data_size);
	if(data_size < 0)
		DISG_ERRNO("Tun read failed");
	p_svr->stats.tun_rx ++;
	p_svr->stats.tun_rx_bytes += data_size;

	//first reverse the data
	crc = disg_crc16((uint8_t*)p_rcv_buf, data_size);
	DISG_DBG("[TUN][RECV] %5u [crc] %04x", data_size, crc);
	if(p_svr->p_arg->verbose >=4 )
		disg_hexdump(p_rcv_buf, data_size);

	disg_data_reverse_in_place((uint8_t*)p_rcv_buf, data_size);

#ifdef DISG_LZO_SUPPORT
	if(p_svr->p_arg->lzo)
	{
		// the lzo compression.
		data_size = disg_comp_lzo(data_size, (char*)p_rcv_buf, (char*)p_svr->tx_pkt.lzobuf);
		DISG_DBG("[TUN][Comp] %u", data_size);
		if(data_size <0)
			return 0;
		p_svr->tx_pkt.hdr.lzo = 1;
	}
	else
	{
#endif
		memcpy(p_svr->tx_pkt.lzobuf, p_rcv_buf, data_size);
#ifdef DISG_LZO_SUPPORT
		p_svr->tx_pkt.hdr.lzo = 0;
	}
#endif

	//send it out, with header, we may need to segment it.
	p_svr->tx_pkt.hdr.magic = htonl(DISG_PKT_HDR_MAGIC_DATA);
	p_svr->tx_pkt.hdr.frag = 0;
	p_svr->curr_tx_seq ++;
	p_svr->tx_pkt.hdr.seq = 0;
	p_svr->tx_pkt.hdr.pkt_id = htons(p_svr->curr_tx_seq);
	p_svr->tx_pkt.hdr.size = htons(data_size);
	p_svr->tx_pkt.hdr.crc = htons(crc);


	DISG_DBG("[NET][Send] %5u [crc] %04x [ID] %5u", data_size, crc, ntohs(p_svr->tx_pkt.hdr.pkt_id));

	if(p_svr->p_arg->udp_port_cnt)
	{
		disg_svr_send_msg_udp(p_svr, p_svr->p_conn_list[p_svr->conn_id_udp_tx_curr], data_size);
	}
	else
	{
		disg_svr_process_send_sctp(p_svr, data_size);
	}
	return 0;
}

void disg_svr_alloc_rx_pkt(disg_svr* p_svr)
{
	if(p_svr->p_rx_pkt == NULL)
		p_svr->p_rx_pkt = malloc(sizeof(*p_svr->p_rx_pkt));

	return;
}


void disg_svr_process_sock_recv_done(disg_svr* p_svr, disg_pkt_frag_node* p_rx_node)
{
	int data_size;
	int ret;
	int id_diff = p_rx_node->pkt.hdr.pkt_id - p_svr->last_pkt_id;
	uint16_t crc;
	uint8_t* p_data;

	if(id_diff < 0)
	{
		DISG_ERR("Out of order, diff %d", id_diff);
		p_svr->stats.ooo ++;
	}
	else if(id_diff == 0)
	{
		p_svr->stats.dup ++;
		//dup
		return;
	}
	else if(id_diff != 1)
	{
		DISG_ERR("Gap,          diff %d", id_diff);
		p_svr->stats.gap ++;
	}

	p_svr->last_pkt_id = p_rx_node->pkt.hdr.pkt_id;

	DISG_DBG("[NET][RxFn] %5u [crc] %04x [ID] %5u", p_rx_node->pkt.hdr.size, p_rx_node->pkt.hdr.crc, p_rx_node->pkt.hdr.pkt_id);

	data_size = p_rx_node->pkt.hdr.size;
#ifdef DISG_LZO_SUPPORT
	if(p_rx_node->pkt.hdr.lzo)
	{
		data_size = disg_decomp_lzo(p_rx_node->pkt.hdr.size, (char*)p_rx_node->pkt.lzobuf, (char*) p_svr->decomp_buf);
		if(data_size <0)
			return;
		p_data = p_svr->decomp_buf;
	}
	else
#else
		p_data = p_rx_node->pkt.lzobuf;
#endif
	disg_data_reverse_in_place(p_data, data_size);
	crc = disg_crc16((uint8_t*)p_data, data_size);
	DISG_DBG("[NET][Decp] %5u [crc] %04x [ID] %5u", data_size, crc, p_rx_node->pkt.hdr.pkt_id);
	if(crc != p_rx_node->pkt.hdr.crc)
		DISG_ERR("Invalid crc, in hdr %04x, caculated %04x", p_rx_node->pkt.hdr.crc, crc);

	if(p_svr->p_arg->verbose >=4 )
		disg_hexdump(p_data, data_size);
	crc = disg_crc16((uint8_t*)p_data, data_size);
	if(crc != p_rx_node->pkt.hdr.crc)
	{
		DISG_ERR("Invalid [crc] before TUN write, in hdr %04x, caculated %04x", p_rx_node->pkt.hdr.crc, crc);
	}
	ret = write(p_svr->tun_fd, p_data, data_size);
	crc = disg_crc16((uint8_t*)p_data, data_size);
	if(crc != p_rx_node->pkt.hdr.crc)
	{
		DISG_ERR("Invalid [crc] after TUN write, in hdr %04x, caculated %04x", p_rx_node->pkt.hdr.crc, crc);
		p_svr->stats.crc_error ++;
	}

	DISG_DBG("[TUN][WRIT] %u ", ret);
	if(p_svr->p_arg->verbose >=4 )
		disg_hexdump(p_svr->decomp_buf, data_size);
	if(data_size != ret)
	{
		DISG_ERRNO("Failed to write to tun, return %d requested %d", ret, data_size);
	}

}

void disg_svr_process_remove_frag_after(disg_svr* p_svr, disg_pkt_frag_node* p_prev, disg_pkt_frag_node* p_to_del)
{
	if(p_prev == NULL)
	{
		p_svr->p_rx_frag = p_to_del->p_next;
	}
	else
	{
		p_prev->p_next = p_to_del->p_next;
	}

}
void disg_svr_process_chain_frag_after(disg_svr* p_svr, disg_pkt_frag_node* p_curr, disg_pkt_frag_node* p_to_add)
{
	disg_pkt_frag_node* p_tmp_next;
	if(p_curr == NULL)
	{
		p_to_add->p_next = p_svr->p_rx_frag;
		p_svr->p_rx_frag = p_to_add;
	}
	else
	{
		p_tmp_next = p_curr->p_next;
		p_curr->p_next = p_to_add;
		p_to_add->p_next = p_tmp_next;
	}
}

bool disg_svr_process_udp_recv_frag_finish_inner(disg_svr* p_svr, disg_pkt_frag_node* p_prev, disg_pkt_frag_node* p_first)
{
	disg_pkt_frag_node* p_head = p_first;
	uint32_t comp_off = 0;
	bool deliver = false;
	while(p_head)
	{
		if(p_head->pkt.hdr.pkt_id == p_first->pkt.hdr.pkt_id)
		{
			DISG_FRAG_DBG(p_head, "FRAG Done");
			if(comp_off)
			{
				DISG_FRAG_DBG(p_head, "FRAG Copy off %4u", comp_off);
				memcpy(p_first->pkt.lzobuf + comp_off, p_head->pkt.lzobuf, p_head->pkt.hdr.size);
			}
			comp_off += p_head->pkt.hdr.size;

			if(p_head->pkt.hdr.frag == DISG_PKT_FLAG_FRAG_END)
			{
				deliver = true;
			}

			if(p_head != p_first)
			{//remove this segment, we only need the first to deliver
				p_first->p_next = p_head->p_next;
				DISG_FRAG_DBG(p_head, "FRAG Free");
				free(p_head);
			}

			if(deliver)
			{
				p_first->pkt.hdr.size = comp_off;
				DISG_FRAG_DBG(p_first, "FRAG Deliver ");
				disg_svr_process_sock_recv_done(p_svr, p_first);

				disg_svr_process_remove_frag_after(p_svr, p_prev, p_first);
				DISG_FRAG_DBG(p_first, "FRAG Free First");
				free(p_first);
				break;
			}
		}
		p_head = p_head->p_next;
	}

	return deliver;
}

void disg_svr_process_udp_recv_frag_finish_chk(disg_svr* p_svr, disg_pkt_frag_node* p_prev, disg_pkt_frag_node* p_first)
{
	disg_pkt_frag_node* p_head = p_first;
	uint32_t curr_seq = 0;
	int found = false;

	while(p_head)
	{
		if(p_head->pkt.hdr.pkt_id == p_first->pkt.hdr.pkt_id)
		{
			found = true;
			DISG_FRAG_DBG(p_head, "FRAG CHK FINISH curr_seq %u", curr_seq );
			if(p_head->pkt.hdr.seq != curr_seq)
			{
				return;
			}
			curr_seq ++;
			if(p_head->pkt.hdr.frag == DISG_PKT_FLAG_FRAG_END)
			{//truelly done, copy and delivery
				if(disg_svr_process_udp_recv_frag_finish_inner(p_svr, p_prev, p_first))
					break;
			}
		}
		else
		{
			if(found)
				break;
		}
		p_head = p_head->p_next;
	}

}

void disg_svr_process_sock_recv_frag(disg_svr* p_svr, disg_pkt_frag_node* p_rx_node)
{
	disg_pkt_frag_node* p_head = p_svr->p_rx_frag, *p_prev;
	disg_pkt_frag_node* p_match_head = NULL, *p_match_head_prev = NULL;

	DISG_FRAG_DBG(p_rx_node, "FRAG RCV ");
	if(p_head == NULL)
	{
		p_svr->p_rx_frag = p_rx_node;
		p_svr->p_rx_frag->p_next = NULL;
		return;
	}

	p_prev = NULL;
	//the list is sorted, first by pkt_id, then by seq
	while(p_head)
	{
		if(p_head->pkt.hdr.pkt_id == p_rx_node->pkt.hdr.pkt_id)
		{
			if(p_match_head == NULL)
			{
				p_match_head_prev = p_prev;
				p_match_head = p_head;
			}
			if(p_head->pkt.hdr.seq < p_rx_node->pkt.hdr.seq)
			{//chain after
				goto NXT_FRAG;
			}
			else if (p_head->pkt.hdr.seq > p_rx_node->pkt.hdr.seq)
			{//chain before
				if(p_match_head == p_head)
					p_match_head = p_rx_node;
				DISG_FRAG_DBG(p_rx_node, "FRAG RCV chain before %08x.%u",
						p_prev?p_prev->pkt.hdr.pkt_id:0, p_prev?p_prev->pkt.hdr.seq:0);
				disg_svr_process_chain_frag_after(p_svr, p_prev, p_rx_node);
				//we might be head
				break;
			}
			else
			{
				DISG_FRAG_DBG(p_rx_node, "FRAG DUP, Free");
				free(p_rx_node);
				return;
			}

		}
		else
		{
			if(p_match_head)
			{//chain after previous
				DISG_FRAG_DBG(p_rx_node, "FRAG RCV, chain aftera %08x.%u",
						p_prev?p_prev->pkt.hdr.pkt_id:0, p_prev?p_prev->pkt.hdr.seq:0);
				disg_svr_process_chain_frag_after(p_svr, p_prev, p_rx_node);
				break;
			}
		}
NXT_FRAG:
		p_prev = p_head;
		p_head = p_head->p_next;
	}

	if(p_head == NULL)
	{//reaching end of loop, we need to insert it to the tail
		p_svr->stats.frag_list
		DISG_FRAG_DBG(p_rx_node, "FRAG RCV, chain afterb %08x.%u",
				p_prev?p_prev->pkt.hdr.pkt_id:0, p_prev?p_prev->pkt.hdr.seq:0);
		disg_svr_process_chain_frag_after(p_svr, p_prev, p_rx_node);
	}
	if(p_match_head)
	{//we found a match, try deliver
		disg_svr_process_udp_recv_frag_finish_chk(p_svr, p_match_head_prev, p_match_head);
	}

}

int disg_svr_save_stats(disg_svr* p_svr)
{
	int fd;
    char tempfilepath[255];
    FILE* p_file;
    disg_stats stats = p_svr->stats;

    strncpy(tempfilepath, p_svr->p_arg->stats_path, 100);
    tempfilepath[100] = '\0';
    strncat(tempfilepath, ".XXXXXX", 255);

    // create and open temp file
    fd = mkstemp(tempfilepath);
    if(fd < 0)
        return -1;
    p_file = fdopen(fd, "w");
    if(p_file == NULL)
    {
    	close(fd);
    	return -1;
    }

    fprintf(p_file, "TUN_RX     %16"PRIu64"\n", stats.tun_rx);
    fprintf(p_file, "TUN_TX     %16"PRIu64"\n", stats.tun_tx);
    fprintf(p_file, "IP__RX     %16"PRIu64"\n", stats.ip_rx);
    fprintf(p_file, "CRCERR     %16"PRIu64"\n", stats.crc_error);
    fprintf(p_file, "IP__TX     %16"PRIu64"\n", stats.ip_tx);
    fprintf(p_file, "PINGRX     %16"PRIu64"\n", stats.ping_rx);
    fprintf(p_file, "NOISE      %16"PRIu64"\n", stats.noise_rx);
    fprintf(p_file, "TUN_RX_B   %16"PRIu64"\n", stats.tun_rx_bytes);
    fprintf(p_file, "TUN_TX_B   %16"PRIu64"\n", stats.tun_tx_bytes);
    fprintf(p_file, "IP__RX_B   %16"PRIu64"\n", stats.ip_rx_bytes);
    fprintf(p_file, "IP__TX_B   %16"PRIu64"\n", stats.ip_tx_bytes);

    fclose(p_file);
    if(rename(tempfilepath, p_svr->stats_file) < 0)
    {
        remove(tempfilepath);
        return -1;
    }

    return 0;
}

int disg_svr_process_sock_recv(disg_svr* p_svr, disg_conn* p_conn, int data_size)
{
	disg_pkt_frag_node* p_rx_node = p_svr->p_rx_pkt;

	p_rx_node->pkt.hdr.magic = ntohl(p_rx_node->pkt.hdr.magic);
	p_rx_node->pkt.hdr.crc = ntohs(p_rx_node->pkt.hdr.crc);
	p_rx_node->pkt.hdr.pkt_id = ntohs(p_rx_node->pkt.hdr.pkt_id);
	p_rx_node->pkt.hdr.size = ntohs(p_rx_node->pkt.hdr.size);
	p_rx_node->age = 0;
	p_rx_node->p_next = NULL;
	DISG_DBG("[NET][Recv] %5u [crc] %04x [ID] %5u", data_size, p_rx_node->pkt.hdr.crc, p_rx_node->pkt.hdr.pkt_id);

	if(p_rx_node->pkt.hdr.magic != DISG_PKT_HDR_MAGIC_DATA)
	{
		if(p_rx_node->pkt.hdr.magic == DISG_PKT_HDR_MAGIC_PING)
		{
			DISG_INFO("Received PING from %08x.%5u", DISG_GET_SADDR_ADDR(p_conn->remote_addr),
					p_conn->port);
			p_conn->ping_fail_cnt = 0;
			p_conn->failed = false;
			disg_svr_send_ping(p_svr, p_conn, true, false);
			//this is valid ping of official channel
			p_svr->stats.ping_rx ++;
			return 1;
		}
		else if(p_rx_node->pkt.hdr.magic == DISG_PKT_HDR_MAGIC_PING_BACK)
		{
			DISG_INFO("Received PING from %08x.%5u", DISG_GET_SADDR_ADDR(p_conn->remote_addr),
					p_conn->port);
			p_conn->ping_fail_cnt = 0;
			p_conn->failed = false;
			disg_svr_send_ping(p_svr, p_conn, true, true);
			//this is valid ping for backup channel, no switching channel
			p_svr->stats.ping_rx ++;
			return 0;
		}
		else if(p_rx_node->pkt.hdr.magic == DISG_PKT_HDR_MAGIC_PING_ACK)
		{
			DISG_INFO("Received PING ACK from %08x.%5u", DISG_GET_SADDR_ADDR(p_conn->remote_addr),
					p_conn->port);
			p_conn->ping_fail_cnt = 0;
			p_conn->failed = false;
			p_svr->stats.ping_rx ++;
			return 0;
		}
		else
			p_svr->stats.noise_rx ++;
		return 0;
	}
	p_conn->ping_fail_cnt = 0;
	p_conn->failed = false;
	p_svr->stats.ip_rx ++;
	p_svr->stats.ip_rx_bytes += data_size;

	//magic verified, switch to this conn
	if(p_conn && p_svr->p_arg->sctp_port_enable)
	{
		if(p_svr->p_arg->peer == NULL)
		{//we are sctp server,
			if(p_svr->sctp_conn != p_conn)
			{//we need to switch to this new connection
				p_svr->sctp_conn = p_conn;
				disg_svr_conn_remove_other(p_svr, p_conn);
			}
		}
	}

	if(p_rx_node->pkt.hdr.frag == 0)
	{
		disg_svr_process_sock_recv_done(p_svr, p_rx_node);
		//will reuse rx_node
	}
	else
	{
		disg_svr_process_sock_recv_frag(p_svr, p_rx_node);
		p_svr->p_rx_pkt = NULL;
	}
	return 1;
}

int disg_svr_udp_receive_data(disg_svr* p_svr, struct pollfd* p_pollfd)
{
	int data_size;
	int data_valid;
	disg_conn* p_conn;

	while(1)
	{
		p_svr->saddr_len = sizeof(p_svr->recv_addr);
		disg_svr_alloc_rx_pkt(p_svr);
		if(p_svr->p_rx_pkt == NULL)
			break;
		data_size = recvfrom(p_pollfd->fd, &(p_svr->p_rx_pkt->pkt), DISG_UDP_RCV_BUF_SIZE, MSG_DONTWAIT,
							(struct sockaddr*)&p_svr->recv_addr, &p_svr->saddr_len);
		if(data_size <0)
		{
			if(errno != EAGAIN)
				DISG_ERRNO("recvfrom failed");
			return -1;
		}

		p_svr->p_rx_pkt->data_size = data_size;
		p_conn = p_svr->p_conn_list_by_sock[p_pollfd->fd];
		if(p_conn == NULL)
		{
			DISG_ERR("NULL connection sock %d", p_pollfd->fd);
		}

		//return 0 means data is valid
		data_valid = disg_svr_process_sock_recv(p_svr, p_conn, data_size);

		if(p_svr->p_arg->peer == NULL)
		{//server
			if(data_valid == 1 || (p_svr->peer_set != 1 && data_valid==0))
			{//data is valid
				if(p_svr->peer_addr.sin_addr.s_addr != p_svr->recv_addr.sin_addr.s_addr ||
						p_svr->peer_addr.sin_port != p_svr->recv_addr.sin_port)
				{
					char addr_old[32];
					char addr_new[32];
					uint16_t new_port = ntohs(p_svr->recv_addr.sin_port);
					if(new_port >= p_svr->p_arg->base_port + p_svr->port_cnt)
					{
						DISG_ERR("Invalid port from client %u", new_port);
						continue;
					}
					strncpy(addr_old, inet_ntoa(p_svr->peer_addr.sin_addr),18);
					strncpy(addr_new, inet_ntoa(p_svr->recv_addr.sin_addr),18);
					DISG_LOG("Switch remote addr from %15s.%05u to %15s.%05u",
							addr_old, ntohs(p_svr->peer_addr.sin_port),
							addr_new, ntohs(p_svr->recv_addr.sin_port));


					memcpy(&p_svr->peer_addr, &p_svr->recv_addr, p_svr->saddr_len);
					p_svr->peer_addr_len = p_svr->saddr_len;
					p_svr->peer_set = 1;
					p_svr->conn_id_udp_tx_curr = new_port - p_svr->p_arg->base_port;
				}
			}
		}
	}

	return 0;
}

void disg_svr_frag_age_process(disg_svr* p_svr, int age)
{
	disg_pkt_frag_node* p_head = p_svr->p_rx_frag, *p_prev = NULL, *p_tmp;

	while(p_head)
	{
		p_head->age+=age;
		if(p_head->age > 1024)
		{
			p_tmp = p_head->p_next;
			DISG_FRAG_DBG(p_head, "FRAG AGE RMV age %u", p_head->age);
			disg_svr_process_remove_frag_after(p_svr, p_prev, p_head);
			free(p_head);
			p_head = p_tmp;
			//p_prev is not changed
			continue;
		}
		p_prev=p_head;
		p_head = p_head->p_next;
	}

}


int disg_svr_sctp_receive_msg(disg_svr* p_svr, disg_conn* p_conn)
{
#if 0
	struct sctp_sndrcvinfo sndrcvinfo;
	int recv_msg_flags;
	int data_size;

	disg_svr_alloc_rx_pkt(p_svr);
	if(p_svr->p_rx_pkt == NULL)
		return -1;
	data_size = sctp_recvmsg( p_conn->sock, &(p_svr->p_rx_pkt->pkt), DISG_UDP_RCV_BUF_SIZE,
						(struct sockaddr *)NULL, 0, &sndrcvinfo, &recv_msg_flags );

	if(data_size < 0)
	{
		fprintf(stderr, "Failed in sctp_recv_msg, error %d %s\n", errno, strerror(errno));
		return 0;
	}
	if(data_size == 0)
	{
		DISG_LOG("Peer connection closed");
		disg_svr_close_sctp_conn(p_svr, p_conn);
		return 0;
	}
	p_svr->p_rx_pkt->data_size = data_size;

	DISG_DBG("[SCP][Recv] %5u", data_size);
	disg_svr_process_sock_recv(p_svr, p_conn, data_size);
	return 0;
#else
	return 0;
#endif
}



int disg_svr_sctp_svr_conn_accept(disg_svr* p_svr)
{
	int ret;
	struct sockaddr remote_addr;
	socklen_t slen = sizeof(remote_addr);
	disg_conn* p_conn;

	DISG_CALL_INIT(accept, p_svr->sctp_listen_sock, &remote_addr, &slen);

	p_conn = disg_svr_conn_add_new(p_svr, ret, &remote_addr, slen);
	if(p_conn)
	{
		DISG_ERR("Failed to accept connection");
		return -1;
	}

	//if we are not connected, mark as connected.
	if(p_svr->sctp_conn == NULL)
	{
		p_svr->sctp_conn = p_conn;
	}
	return 0;
ERR_RET:
	return -1;
}

void disg_svr_client_switch_port_backup(disg_svr* p_svr)
{
	disg_conn* p_new_backup_conn;
	if(p_svr->p_arg->udp_port_cnt > 8)
	{
		p_svr->conn_id_udp_tx_backup+=7;

		if(p_svr->conn_id_udp_tx_backup >= p_svr->p_arg->udp_port_cnt)
			p_svr->conn_id_udp_tx_backup -= p_svr->p_arg->udp_port_cnt;
		//backup port should not be the same as curr
		if(p_svr->conn_id_udp_tx_backup == p_svr->conn_id_udp_tx_curr)
		{
			p_svr->conn_id_udp_tx_backup+=7;
			if(p_svr->conn_id_udp_tx_backup >= p_svr->p_arg->udp_port_cnt)
				p_svr->conn_id_udp_tx_backup -= p_svr->p_arg->udp_port_cnt;
			if(p_svr->conn_id_udp_tx_backup == p_svr->conn_id_udp_tx_curr)
			{
				DISG_LOG("New backup port is same as curr port %u",
						p_svr->p_conn_list[p_svr->conn_id_udp_tx_backup]->port);
				return;
			}
		}
		p_new_backup_conn = p_svr->p_conn_list[p_svr->conn_id_udp_tx_backup];
		p_new_backup_conn->ping_fail_cnt = 0;
		//mark new backup is failed, until we receive something.
		//help to prevent we switch before we found a good port
		p_new_backup_conn->failed = true;
		DISG_LOG("New backup port is %u",
				p_svr->p_conn_list[p_svr->conn_id_udp_tx_backup]->port);
	}

}

void disg_svr_client_switch_port(disg_svr* p_svr)
{
	if(!p_svr->p_conn_list[p_svr->conn_id_udp_tx_backup]->failed)
	{
		DISG_LOG("Switch from port %u to port %u",
				p_svr->p_conn_list[p_svr->conn_id_udp_tx_curr]->port,
				p_svr->p_conn_list[p_svr->conn_id_udp_tx_backup]->port);
		p_svr->conn_id_udp_tx_curr = p_svr->conn_id_udp_tx_backup;
		disg_svr_client_switch_port_backup(p_svr);
	}
	else
	{
		DISG_LOG("No good backup connection, not switching");
	}
}

void disg_svr_client_check_backup_conn(disg_svr* p_svr)
{
	disg_conn* p_conn = p_svr->p_conn_list[p_svr->conn_id_udp_tx_backup];

	disg_svr_send_ping(p_svr, p_conn, false, true);

	//backup connection checking is half of the time, so it fails early than a normal one.
	if(p_conn->ping_fail_cnt > ((p_svr->p_arg->max_ping_fail>>1) + 1))
	{
		p_conn->failed = true;
		disg_svr_client_switch_port_backup(p_svr);
	}
	p_conn->ping_fail_cnt ++;
}

void disg_svr_client_check_conn_curr(disg_svr* p_svr)
{
	disg_conn*p_conn_curr;
	p_conn_curr = p_svr->p_conn_list[p_svr->conn_id_udp_tx_curr];
	if(p_svr->stats.ip_rx == p_svr->stats_old.ip_rx)
	{//no packets received since last packet. send a hb.
		disg_svr_send_ping(p_svr, p_conn_curr, false, false);
	}
	if(p_conn_curr->ping_fail_cnt > p_svr->p_arg->max_ping_fail)
	{
		disg_svr_client_switch_port(p_svr);
	}

	p_conn_curr->ping_fail_cnt ++;

}

void disg_svr_timer_process(disg_svr* p_svr)
{
	time_t curr_sec = time(NULL);

	if(curr_sec != p_svr->last_timer_sec)
	{
		if(p_svr->p_arg->peer != NULL)
		{//client
			disg_svr_client_check_conn_curr(p_svr);
			if(p_svr->p_arg->udp_port_cnt > 1)
				disg_svr_client_check_backup_conn(p_svr);
		}
	}
	p_svr->last_timer_sec = curr_sec;
	localtime_r(&p_svr->last_timer_sec, &p_svr->time_tm);
	strftime(p_svr->time_str, sizeof(p_svr->time_str) -1, "%F-%T", &p_svr->time_tm);
	p_svr->stats_old = p_svr->stats;

	if(p_svr->last_timer_sec %5 == 0)
	{
		disg_svr_save_stats(p_svr);
	}
}

int disg_svr_run(disg_svr* p_svr)
{
	uint32_t loop;
	int ret;

	p_svr->running = 1;
	while(p_svr->running)
	{
		disg_svr_timer_process(p_svr);
		for(loop = 0; loop < p_svr->pollfd_cnt; loop++)
		{
			p_svr->pollfd_arr[loop].events = POLLIN;
			p_svr->pollfd_arr[loop].revents = 0;
		}
		ret = poll(p_svr->pollfd_arr, p_svr->pollfd_cnt, 1000);
		if(ret==0)
		{
			disg_svr_frag_age_process(p_svr, 100);
			continue;
		}
		if(ret<0)
		{
			if(errno == EINTR)
				continue;
			else
			{
				DISG_ERRNO("poll failed");
			}
		}

		disg_svr_frag_age_process(p_svr, 1);
		
		if(p_svr->pollfd_arr[0].revents & POLLIN)
		{//tun interface
			disg_svr_process_tun_recv_data(p_svr);
		}
		//udp sockets
		for(loop = 1; loop <= p_svr->port_cnt; loop++)
		{
			if(p_svr->pollfd_arr[loop].revents & POLLIN)
			{
				disg_svr_udp_receive_data(p_svr, &p_svr->pollfd_arr[loop]);
			}
		}
		if(p_svr->p_arg->sctp_port_enable)
		{
			//sctp sockets
			if(p_svr->p_arg->peer == NULL)
			{
				if(p_svr->pollfd_arr[p_svr->pollfd_sctp_listen].revents & POLLIN)
				{
					disg_svr_sctp_svr_conn_accept(p_svr);
				}
			}
			for(loop = p_svr->pollfd_sctp_conn_base; loop < p_svr->pollfd_cnt; loop++)
			{
				if(p_svr->pollfd_arr[loop].revents & POLLIN)
				{
					disg_svr_sctp_receive_msg(p_svr, p_svr->p_conn_list[loop-p_svr->pollfd_sctp_conn_base]);
				}
			}
		}
	}


	return 0;
}




int disg_svr_init_tun(disg_svr* p_svr)
{
	int fd;

	fd = disg_tun_open(p_svr->p_arg->device);
	if(fd < 0)
		return -1;

	p_svr->tun_fd = fd;
	//poll fd for tun
	p_svr->pollfd_arr[0].fd = p_svr->tun_fd;
	p_svr->pollfd_cnt = 1;

	return 0;
}

int disg_svr_init_udp_server(disg_svr* p_svr, disg_arg* p_arg)
{
	uint32_t loop;
	int sock;

	if(p_arg->udp_port_cnt > DISG_MAX_PORT)
	{
		DISG_ERR("Too many port %u > %u", p_arg->udp_port_cnt, DISG_MAX_PORT);
		return -1;
	}
	if(p_arg->base_port + p_arg->udp_port_cnt > 65536)
	{
		DISG_ERR("Port is larger than 65536");
		return -1;
	}

	p_svr->port_base = p_arg->base_port;
	p_svr->port_cnt = p_arg->udp_port_cnt;


	//port array is 1 based
	struct sockaddr_in peer_addr;

	memset(&peer_addr, 0, sizeof(peer_addr));

	p_svr->conn_id_udp_tx_curr = 0;
	if(p_svr->p_arg->udp_port_cnt > 8)
		p_svr->conn_id_udp_tx_backup = 7;
	else
		p_svr->conn_id_udp_tx_backup = 0;
	for(loop = 1; loop <= p_arg->udp_port_cnt; loop++)
	{
		uint32_t port = p_arg->base_port + loop - 1;
		sock = disg_sock_create(p_svr, port);
		if(sock<0)
		{
			DISG_ERR("Failed to create sock for port %u, error %s(%d)", p_arg->base_port + loop, strerror(errno), errno);
			return -1;
		}
//		p_svr->udp_sock_arr[loop] = sock;
//		p_svr->udp_port_arr[loop] = port;
//		p_svr->pollfd_arr[loop].fd = sock;
		peer_addr.sin_port = htons(port);
		disg_svr_conn_add_new(p_svr, sock, (struct sockaddr*)&peer_addr, sizeof(peer_addr));
	}

	return 0;
}

int disg_svr_init_sctp_server(disg_svr* p_svr)
{
#if 0
	int ret;
	struct sockaddr_in servaddr;
	struct sctp_initmsg initmsg;
//	struct sctp_event_subscribe events;
	//char buffer[MAX_BUFFER+1];

	DISG_CALL_INIT(socket, AF_INET, SOCK_STREAM, IPPROTO_SCTP);
	p_svr->sctp_listen_sock = ret;

	memset(&servaddr, 0, sizeof(servaddr) );
	servaddr.sin_family = AF_INET;
	servaddr.sin_addr.s_addr = htonl( INADDR_ANY );
	servaddr.sin_port = htons(p_svr->p_arg->sctp_port);

	DISG_CALL_INIT(bind, p_svr->sctp_listen_sock, (struct sockaddr *)&servaddr, sizeof(servaddr) );

	/* Specify that a maximum of 5 streams will be available per socket */
	memset( &initmsg, 0, sizeof(initmsg) );
	initmsg.sinit_num_ostreams = 5;
	initmsg.sinit_max_instreams = 5;
	initmsg.sinit_max_attempts = 4;
	DISG_CALL_INIT(setsockopt, p_svr->sctp_listen_sock, IPPROTO_SCTP, SCTP_INITMSG,
					 &initmsg, sizeof(initmsg) );

	DISG_CALL_INIT(listen, p_svr->sctp_listen_sock, 100);
	return 0;
ERR_RET:
	return -1;
#else
	return 0;
#endif
}



int disg_svr_init_peer_addr(disg_svr* p_svr, disg_arg* p_arg)
{
	struct hostent* p_host;
	p_host = gethostbyname(p_svr->p_arg->peer);
	if(p_host == NULL)
	{
		DISG_ERRNO("Can't resolve peer host name %s", p_svr->p_arg->peer);
		return -1;
	}
	memset(&p_svr->peer_addr, 0, sizeof(p_svr->peer_addr));
	memcpy(&p_svr->peer_addr.sin_addr, p_host->h_addr_list[0], sizeof(p_svr->peer_addr.sin_addr));
	{
		uint8_t* p_8 = (void*)&p_svr->peer_addr.sin_addr;
		DISG_LOG("Peer addr %u.%u.%u.%u", p_8[0], p_8[1], p_8[2], p_8[3]);
	}
	p_svr->peer_addr.sin_port = htons(p_svr->port_base);
	p_svr->peer_addr.sin_family = AF_INET;
	p_svr->peer_addr_len = sizeof(p_svr->peer_addr);
	p_svr->peer_set = 1;

	return 0;
}

void disg_arg_dump(disg_svr* p_svr, disg_arg* p_arg)
{
	if(p_arg->peer)
		DISG_LOG("Running as client mode, server is %s", p_arg->peer);
	else
		DISG_LOG("Running as server mode");
	DISG_LOG("TUN devide is %s", p_arg->device);

	if(p_arg->udp_port_cnt)
		DISG_LOG("UDP mode enabled. Base port is %5u, max port is %5u",
				p_arg->base_port, p_arg->base_port+p_arg->udp_port_cnt);
	if(p_arg->sctp_port_enable)
		DISG_LOG("SCTP mode enabled. Sctp port is %5u", p_arg->sctp_port);
	DISG_LOG("MAX ping fail is %u", p_arg->max_ping_fail);
	DISG_LOG("Extra fragment packet is %s.", p_arg->extra_frag ? "enabled":"disabled");

}
disg_svr* disg_svr_create(disg_arg* p_arg)
{
	int ret;
	pthread_t th;
	disg_svr* p_svr = &g_disg_svr;

	memset(p_svr, 0, sizeof(*p_svr));

	p_svr->p_arg = p_arg;
	disg_arg_dump(p_svr, p_arg);
	p_svr->last_timer_sec = time(NULL);
	localtime_r(&p_svr->last_timer_sec, &p_svr->time_tm);
	strftime(p_svr->time_str, sizeof(p_svr->time_str) -1, "%F-%T", &p_svr->time_tm);

	//always init tun first, tun dev uses the the first slot in the poll array
	DISG_CALL_INIT(disg_svr_init_tun, p_svr);

	if(p_svr->p_arg->udp_port_cnt)
	{
		DISG_CALL_INIT(disg_svr_init_udp_server, p_svr, p_arg);
	}

	if(p_svr->p_arg->peer)
	{
		DISG_CALL_INIT(disg_svr_init_peer_addr, p_svr, p_arg);
		if(p_svr->p_arg->sctp_port_enable)
			DISG_CALL_INIT(pthread_create, &th, NULL, disg_svr_sctp_client_conn_thread, p_svr);
	}
	else
	{
		if(p_svr->p_arg->sctp_port_enable)
		{
			DISG_CALL_INIT(disg_svr_init_sctp_server, p_svr);
		}
	}


	//poll fd for udp
	//p_svr->pollfd_cnt += p_svr->port_cnt;

	//poll fd for sctp listen
	if(p_svr->p_arg->sctp_port_enable)
	{
		if(p_svr->p_arg->peer == NULL)
		{
			p_svr->pollfd_arr[p_svr->pollfd_cnt].fd = p_svr->sctp_listen_sock;
			p_svr->pollfd_sctp_listen = p_svr->pollfd_cnt;
			p_svr->pollfd_cnt ++;
		}
		p_svr->pollfd_sctp_conn_base = p_svr->pollfd_cnt;
	}

	snprintf(p_svr->stats_file, 511, "%s/disg_%s_stats", p_svr->p_arg->stats_path, p_svr->p_arg->device);
	return p_svr;

ERR_RET:
	return NULL;
}

