#!/bin/bash

set -x
set -e

# Make sure only root can run our script
if [ "$(id -u)" != "0" ]; then
   echo "This script must be run as root" 1>&2
   exit 1
fi

# update and install tools
yum update -y
yum upgrade -y
yum install epel-release
yum install net-tools vim htop wget firewalld -y
yum groupinstall 'Development Tools'  -y

cd /tmp
wget -U ossec http://www.ossec.net/files/ossec-hids-2.8.1.tar.gz
wget -U ossec http://www.ossec.net/files/ossec-hids-2.8.1-checksum.txt
tar -zxvf ossec-hids-2.8.1.tar.gz
cd ossec-hids-2.8.1
./install.sh

#start ossec
/var/ossec/bin/ossec-control start

# firewall rules
systemctl enable firewalld
systemctl start firewalld
firewall-cmd --permanent --zone=public --add-port=22/tcp
firewall-cmd --permanent --zone=public --add-port=1514/udp
firewall-cmd --reload


#
