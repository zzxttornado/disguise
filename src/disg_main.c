/*
 ============================================================================
 Name        : disguise.c
 Author      : Jeff Zheng
 Version     :
 Copyright   : GPLv2
 Description : Hello World in C, Ansi-style
 ============================================================================
 */

#include "disg_common.h"
#include "disg_svr.h"
#include "popt.h"
#include "disg_lzo.h"
/*
 * Disguise VPN, connect two end point and create tun device for routing.
 *
 * IP to IP tunnel.
 *
 * Open a large number of UDP ports to accept incoming traffic.
 *
 * Use SSL private key CHAP to do Auth.
 *
 * The server listens on all opened ports, when a packet is received,
 * The packet is inspected, it could be either
 * 1. invalid,
 * 2. with a valid hash, and will goto deliver
 * 3. auth request. Each connection is given a hash.
 *
 */


typedef enum disg_arg_type_e
{
	DISG_OPT_HELP = 1,
	DISG_OPT_DEV_NAME,
	DISG_OPT_BASE_PORT,
	DISG_OPT_PORT_CNT,
	DISG_OPT_SCTP_PORT,
	DISG_OPT_EXTRA_FRAG,
	DISG_OPT_PEER,
	DISG_OPT_STATS_PATH,
	DISG_OPT_MAX_PING_FAIL,
#ifdef DISG_LZO_SUPPORT
	DISG_OPT_LZO,
#endif
	DISG_OPT_VERBOSE,
}disg_arg_type;


/**
 *
 * @return
 */
int g_disg_verbose = 1;

int main(int argc, const char* argv[])
{
	int code;
	disg_arg arg = {
			.device		= "tun0",
			.base_port	= 0,
			.udp_port_cnt	= 0,
			.sctp_port	= 0,
			.sctp_port_enable	= false,
			.stats_path = "/dev/shm/",
			.max_ping_fail = 8,
			.verbose	= 1,
			.peer		= NULL,
			.extra_frag	= false,
#ifdef DISG_LZO_SUPPORT
			.lzo		= false,
#endif
	};

	disg_svr* p_svr;

	const struct poptOption option_table[] =
	{
		{ "device",		'd', POPT_ARG_STRING,	&arg.device,			DISG_OPT_DEV_NAME,
				"Tun device name",	"Device name" },
		{ "peer",		'p', POPT_ARG_STRING,	&arg.peer,				DISG_OPT_PEER,
				"Peer address",		"Peer address" },
		{ "base-port",	'b', POPT_ARG_INT,		&arg.base_port,			DISG_OPT_BASE_PORT,
				"Base listen port", "port number" },
		{ "port-count",	'c', POPT_ARG_INT,		&arg.udp_port_cnt,		DISG_OPT_PORT_CNT,
				"Total port to be used", "number" },
		{ "sctp-port",	's', POPT_ARG_INT,		&arg.sctp_port,			DISG_OPT_SCTP_PORT,
				"Enable sctp and specify sctp port", "number" },
		{ "max-ping-fail",	'F', POPT_ARG_INT,	&arg.max_ping_fail,		DISG_OPT_MAX_PING_FAIL,
				"Max ping fail before switching to a different port", "number" },
		{ "stats-path",	's', POPT_ARG_STRING | POPT_ARGFLAG_SHOW_DEFAULT,	&arg.stats_path,		DISG_OPT_STATS_PATH,
				"Path for saving stats", "path" },
		{ "extra-frag",	'x', POPT_ARG_NONE,		NULL,					DISG_OPT_EXTRA_FRAG,
				"Add an extra fragment package", NULL },
#ifdef DISG_LZO_SUPPORT
		{ "enable-lzo",	'l', POPT_ARG_NONE,		NULL,					DISG_OPT_LZO,
				"Enable lzo compression", NULL },
#endif
		{ "verbose",	'v', POPT_ARG_NONE,		NULL,					DISG_OPT_VERBOSE,
				"Verbose printing, will print a stats line per second", NULL },
		POPT_AUTOHELP
		POPT_TABLEEND
	};
	poptContext option_context;


	option_context = poptGetContext(argv[0], argc, argv, option_table, 0);

	if (argc < 2)
	{
		poptPrintUsage(option_context, stderr, 0);
		exit(1);
	}


	while ((code = poptGetNextOpt(option_context)) >= 0)
	{
		switch (code)
		{
		case DISG_OPT_DEV_NAME:
			break;
		case DISG_OPT_PEER:
			break;
		case DISG_OPT_BASE_PORT:
			if(arg.base_port < 0 || arg.base_port>=65534)
			{
				DISG_ERR("Invalid base port %d", arg.base_port);
				return -1;
			}
			break;
		case DISG_OPT_SCTP_PORT:
			if(arg.sctp_port < 0 || arg.sctp_port>=65534)
			{
				DISG_ERR("Invalid base port %d", arg.base_port);
				return -1;
			}
			arg.sctp_port_enable = true;
			break;
		case DISG_OPT_PORT_CNT:
			if(arg.udp_port_cnt < 0 || arg.udp_port_cnt>=65534)
			{
				DISG_ERR("Invalid port count %d", arg.udp_port_cnt);
				return -1;
			}
			break;
		case DISG_OPT_EXTRA_FRAG:
			arg.extra_frag = true;
			break;
		case DISG_OPT_MAX_PING_FAIL:
			break;
		case DISG_OPT_STATS_PATH:
			break;
#ifdef DISG_LZO_SUPPORT
		case DISG_OPT_LZO:
			arg.lzo = true;
			break;
#endif
		case DISG_OPT_VERBOSE:
			arg.verbose ++;
			break;
		}
	}
	g_disg_verbose = arg.verbose;
	if(arg.base_port + arg.base_port>= 65535)
	{
		DISG_ERR("Invalid port base and count %d, %d, %d", arg.base_port, arg.udp_port_cnt, arg.base_port + arg.base_port);
		return -1;
	}
	disg_lzo_init();

	p_svr = disg_svr_create(&arg);
	if(p_svr==NULL)
		return -1;

	disg_svr_run(p_svr);

	diag_free_lzo();
	return 0;
}

