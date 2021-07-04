#MgXHtEVtSEaHW7x
#3bCS8d7PaffZ6fY
#cBLSFRX8ASezL3G

#1n82p56zQe6TSXNrmE

while true; do
echo "Install node type 1 or 2"
read nodetype
if [ "${nodetype}" == 1 ] || [ "${nodetype}" == 2 ] ; then
  echo "Installing node type ${nodetype}"
  echo -n ${nodetype} > /etc/disg_type
  break
fi
done



yum install -y gcc lksctp-tools-devel popt-devel lzo-devel net-tools tcpdump git autoconf automake
rm -rf disguise
git clone https://github.com/zzxttornado/disguise.git
cd disguise
#git pull
./configure
make
make install

cp scripts/disg.service /usr/lib/systemd/system/
cp scripts/disg_start_hub_v2.sh /root/
cp scripts/disg_start.sh /root/
cp scripts/disg.conf /etc/rsyslog.d/
systemctl daemon-reload
systemctl enable disg
systemctl start disg

firewall-cmd --permanent --zone=external --add-port 43125/tcp
firewall-cmd --permanent --zone=external --add-port 10000-65000/udp
firewall-cmd --permanent --zone=external --add-masquerade

firewall-cmd --permanent --zone=trusted --add-interface=tun0
firewall-cmd --permanent --zone=trusted --add-interface=tun1
firewall-cmd --permanent --zone=trusted --add-interface=tun2


firewall-cmd --zone=external --add-port 43125/tcp
firewall-cmd --zone=external --add-port 10000-65000/udp
firewall-cmd --zone=external --add-masquerade

firewall-cmd --zone=public --remove-interface eth0;firewall-cmd --zone=external --add-interface eth0

firewall-cmd --zone=trusted --add-interface=tun0
firewall-cmd --zone=trusted --add-interface=tun1
firewall-cmd --zone=trusted --add-interface=tun2

echo "net.ipv4.ip_forward=1" > /etc/sysctl.d/80-forwarding.conf
sysctl -w net.ipv4.ip_forward=1

echo "ZONE=external" >> /etc/sysconfig/network-scripts/ifcfg-eth0

firewall-cmd --permanent --zone=work --remove-interface=tun0
firewall-cmd --permanent --zone=work --remove-interface=tun1
firewall-cmd --permanent --zone=work --remove-interface=tun2
firewall-cmd --permanent --zone=trusted --remove-interface=tun2
firewall-cmd --permanent --zone=work --add-interface=tun2

firewall-cmd --zone=trusted --remove-interface=tun2
firewall-cmd --zone=work --add-interface=tun2
firewall-cmd --zone=trusted --add-interface=tun2
firewall-cmd --zone=work --remove-interface=tun2

firewall-cmd --permanent --zone=external --add-port 43125/tcp
firewall-cmd --permanent --zone=external --add-port 10000-65000/udp
firewall-cmd --permanent --zone=external --add-masquerade

firewall-cmd --zone=external --add-port 43125/tcp
firewall-cmd --zone=external --add-port 10000-65000/udp
firewall-cmd --zone=external --add-masquerade
firewall-cmd --permanent --zone=external --add-interface eth0

firewall-cmd --zone=public --remove-interface eth0;firewall-cmd --zone=external --add-interface eth0


firewall-cmd --permanent --zone=public --remove-masquerade
firewall-cmd --zone=public --remove-masquerade


firewall-cmd --list-all-zones

sysctl -w net.ipv4.ip_forward=1

systemctl daemon-reload
systemctl enable disg
systemctl start disg

