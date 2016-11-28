#!/bin/bash
# Author Ben Bornholm

set -x
set -e

# Make sure only root can run our script
if [ "$(id -u)" != "0" ]; then
   echo "This script must be run as root" 1>&2
   exit 1
fi

echo '[wazuh]
name = WAZUH OSSEC Repository - www.wazuh.com
baseurl = http://ossec.wazuh.com/el/7/x86_64
gpgcheck = 1
gpgkey = http://ossec.wazuh.com/key/RPM-GPG-KEY-OSSEC
enabled = 1
' | tee /etc/yum.repos.d/wazuh.repo

yum install ossec-hids-agent -y
/var/ossec/bin/manage_agents
/var/ossec/bin/ossec-control restart
