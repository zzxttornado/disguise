#!/bin/bash

#set -x
HOME_PORT=14000
HOME_DEV=tun1
FILE_PORT=24000
#FILE_PORT=177
FILE_DEV=tun0
SILC_PORT=11467
SILC_DEV=tun2

function stop_disg
{
	NET=$1
	case $NET in
	home)
		TDEV=${HOME_DEV}
		;;
	silc)
		TDEV=${SILC_DEV}
		;;
	file)
		TDEV=${FILE_DEV}
		;;
	*)
		echo "Invalid type"
		exit 1
		;;
	esac

	KPID=$(ps -ef |grep disg_svr |grep -v grep |grep ${TDEV} |awk '{print $2}'	)
	if [ ! -z "${KPID}" ]; then
		echo "Kill disg_svr pid ${KPID}"
		kill ${KPID}
	fi
}

function start_disg
{
	NET=$1
	case $NET in
	home)
		# this is for home
		/usr/local/bin/disg_svr -d ${HOME_DEV} -b ${HOME_PORT} -c 500 -v | logger -t disg_${NET} &
		disown

		sleep 1
		ifconfig ${HOME_DEV} 192.168.39.9/30
		route add -net 192.168.39.8/30 ${HOME_DEV}
		route add -net 192.168.47.0/24 ${HOME_DEV}
		;;
	silc)
		# this is for silicom
		/usr/local/bin/disg_svr -d ${SILC_DEV} -b ${SILC_PORT} -c 500 -v | logger -t disg_${NET} &
		disown
		sleep 1

		ifconfig ${SILC_DEV} 192.168.36.1/24
		route add -net 192.168.0.0/22 ${SILC_DEV}
		;;
		
	file)		
		# this is for net perf office
		/usr/local/bin/disg_svr -d ${FILE_DEV} -b ${FILE_PORT} -c 500 -v |logger -t disg_${NET} &
		disown
		sleep 1

		ifconfig ${FILE_DEV} 192.168.39.1/30
		route add -net 192.168.23.0/24 ${FILE_DEV}
		route add -net 192.168.39.0/30 ${FILE_DEV}
		route add -net 192.168.49.0/24 ${FILE_DEV}
		route add -net 192.168.51.0/24 ${FILE_DEV}
		route add -net 192.168.159.0/24 ${FILE_DEV}
		;;

	*)
		echo "Invalid type"
		exit 1
		;;
	esac
		
}

if [ -z "$1" ]; then
	echo "Invalid type"
	exit 1
fi

if [ $1 != np1 ] && [ $1 != file ] && [ $1 != silc ] && [ $1 != home ]; then
	echo "Invalid type $1"
	exit 1
fi

stop_disg $1
sleep 1
start_disg $1




