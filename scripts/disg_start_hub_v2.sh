#!/bin/bash

#set -x
HOME_DEV=tun1
FILE_DEV=tun0
SILC_DEV=tun2
if [ "$(cat /etc/disg_type)" == "1" ]; then
HOME_PORT=14000
HOME_IP=192.168.39.9/30
HOME_NET=192.168.39.8/30
FILE_PORT=24000
FILE_IP=192.168.39.1/30
FILE_NET=192.168.39.8/30
SILC_PORT=11467
else
HOME_PORT=14500
HOME_IP=192.168.39.13/30
HOME_NET=192.168.39.12/30
FILE_PORT=23200
FILE_IP=192.168.39.5/30
FILE_NET=192.168.39.4/30
SILC_PORT=11467
fi

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
		ifconfig ${HOME_DEV} ${HOME_IP}
		route add -net ${HOME_NET} ${HOME_DEV}
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

		ifconfig ${FILE_DEV} ${FILE_IP}
		route add -net 192.168.23.0/24 ${FILE_DEV}
		route add -net ${FILE_NET} ${FILE_DEV}
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




