#!/bin/bash
# Author Ben Bornholm

set -x
set -e

# Make sure only root can run our script
if [ "$(id -u)" != "0" ]; then
   echo "This script must be run as root" 1>&2
   exit 1
fi

apt-key adv --fetch-keys http://ossec.wazuh.com/repos/apt/conf/ossec-key.gpg.key
echo -e "deb http://ossec.wazuh.com/repos/apt/ubuntu trusty main" >> /etc/apt/sources.list.d/ossec.list
apt-get update
apt-get install ossec-hids-agent
/var/ossec/bin/manage_agents
sudo /var/ossec/bin/ossec-control restart
