#!/bin/bash

set -x
set -e

# Make sure only root can run our script
if [ "$(id -u)" != "0" ]; then
   echo "This script must be run as root" 1>&2
   exit 1
fi

#update system
apt-get update && apt-get upgrade -y

apt-get install mysql-server libmysqlclient-dev mysql-client apache2 php5 libapache2-mod-php5 php5-mysql php5-curl php5-gd php5-intl php-pear php5-imagick php5-imap php5-mcrypt php5-memcache php5-ming php5-ps php5-pspell php5-recode php5-snmp php5-sqlite php5-tidy php5-xmlrpc php5-xsl

cd /opt
https://bintray.com/artifact/download/ossec/ossec-hids/ossec-hids-2.8.3.tar.gz
tar -xzf ossec-hids-2.8.3.tar.gz
cd src

# set database to mysql
make setdb
cd ..
./install.sh
/var/ossec/bin/ossec-control start

<DATABASE THINGS>
mysql -u ossecuser -p ossec < src/os_dbd/mysql.schema

chmod 640 /var/ossec/etc/ossec.conf
<MAKE CHANGES>
chmod 440 /var/ossec/etc/ossec.conf
/var/ossec/bin/ossec-control enable database
/var/ossec/bin/ossec-control restart

########################
# Setup ossec web
#cd /var/www/html/
#wget https://github.com/ossec/ossec-wui/archive/master.zip
#unzip master.zip
#mv ossec-wui-master/ ossec/
#mkdir ossec/tmp/
#chown www-data: -R ossec/
#chmod 666 /var/www/html/ossec/tmp


######################### Install java ########################
add-apt-repository ppa:webupd8team/java
apt-get update
apt-get install oracle-java8-installer
export JAVA_HOME=/usr/java/jdk1.8.0_60/jre

######################### Install logstash ########################
wget -qO - https://packages.elasticsearch.org/GPG-KEY-elasticsearch | sudo apt-key add -
echo "deb https://packages.elasticsearch.org/logstash/2.1/debian stable main" | sudo tee -a /etc/apt/sources.list
sudo apt-get update && sudo apt-get install logstash

# Copy logstash configs
cd ~
apt-get install git -y
git clone https://github.com/wazuh/ossec-wazuh.git
cp ossec-wazuh/extensions/logstash/01-ossec-singlehost.conf /etc/logstash/conf.d/
cp ossec-wazuh/extensions/elasticsearch/elastic-ossec-template.json /etc/logstash/
update-rc.d logstash defaults 95 10

#GeoIP
curl -O "http://geolite.maxmind.com/download/geoip/database/GeoLiteCity.dat.gz"
gzip -d GeoLiteCity.dat.gz && sudo mv GeoLiteCity.dat /etc/logstash/
usermod -a -G ossec logstash

######################## Install elasticsearch ########################
wget -qO - https://packages.elastic.co/GPG-KEY-elasticsearch | sudo apt-key add -
echo "deb https://packages.elastic.co/elasticsearch/2.x/debian stable main" | sudo tee -a /etc/apt/sources.list.d/elasticsearch-2.x.list
apt-get update && sudo apt-get install elasticsearch
update-rc.d elasticsearch defaults 95 10



sed -i 's/# cluster.name: my-application/cluster.name: ossec/g' /etc/elasticsearch/elasticsearch.yml
sed -i 's/# node.name: node-1/node.name: ossec_node1/g' /etc/elasticsearch/elasticsearch.yml
cp /etc/elasticsearch/elasticsearch.yml /etc/elasticsearch/elasticsearch.yml.bak
echo 'index.number_of_shards: 1
index.number_of_replicas: 0
' >> /etc/elasticsearch/elasticsearch.yml

sudo /etc/init.d/elasticsearch start

#Health checks
curl -XGET localhost:9200
curl -XGET 'http://localhost:9200/_cluster/health?pretty=true'

cd ossec-wazuh/extensions/elasticsearch/ && curl -XPUT "http://localhost:9200/_template/ossec/" -d "@elastic-ossec-template.json"
curl -XGET http://localhost:9200/_template/ossec?pretty
sudo service logstash start

######################## Install kibana ########################
wget -qO - https://packages.elastic.co/GPG-KEY-elasticsearch | sudo apt-key add -
echo "deb http://packages.elastic.co/kibana/4.5/debian stable main" | sudo tee -a /etc/apt/sources.list
apt-get update && sudo apt-get install kibana
sudo update-rc.d kibana defaults 95 10
sed -i 's/# server.host: "0.0.0.0"/server.host: "127.0.0.1"/g' /opt/kibana/config/kibana.yml
service kibana start

######################## Nginx proxy ########################
sudo apt-get update
sudo apt-get install nginx apache2-utils
mkdir /etc/nginx/ssl
openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout /etc/nginx/ssl/kibana.key -out /etc/nginx/ssl/kibana.crt

echo 'server {
       listen 80 default_server;                       #Listen on IPv4
       listen [::]:80;                                 #Listen on IPv6
       return 301 https://$host$request_uri;
}

server {
       listen                 *:443;
       listen                 [::]:443;
       ssl on;
       ssl_certificate        /etc/nginx/ssl/kibana.crt;
       ssl_certificate_key    /etc/nginx/ssl/kibana.key;
       server_name            _;
       access_log             /var/log/nginx/kibana.access.log;
       error_log              /var/log/nginx/kibana.error.log;

       location ~ (/|/app/kibana|/bundles/|/kibana4|/status|/plugins) {
               auth_basic "Restricted";
               auth_basic_user_file /etc/nginx/conf.d/kibana.htpasswd;
               proxy_pass http://127.0.0.1:5601;
       }
}
' | sudo tee /etc/nginx/sites-available/default
htpasswd -c /etc/nginx/conf.d/kibana.htpasswd kibanaadmin
service nginx restart






#
