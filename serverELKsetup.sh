#!/bin/bash
# Author Ben Bornholm
# Source: https://www.digitalocean.com/community/tutorials/how-to-install-elasticsearch-logstash-and-kibana-elk-stack-on-centos-7
# Source: https://www.digitalocean.com/community/tutorials/how-to-secure-nginx-with-let-s-encrypt-on-ubuntu-16-04

set -x
set -e

# Make sure only root can run our script
if [ "$(id -u)" != "0" ]; then
   echo "This script must be run as root" 1>&2
   exit 1
fi

####################### Things needed #######################
yum update -y && yum upgrade -y
yum install epel-release -y
yum install vim wget net-tools -y

####################### Install OSSEC server #######################
yum install make gcc git -y
yum install openssl-devel -y
cd ~
mkdir ossec_tmp && cd ossec_tmp
git clone -b stable https://github.com/wazuh/wazuh.git ossec-wazuh
cd ossec-wazuh
sudo ./install.sh

sudo /var/ossec/bin/ossec-control start

ps aux | grep ossec

####################### Install Java #######################
cd ~
wget --no-cookies --no-check-certificate --header "Cookie: gpw_e24=http%3A%2F%2Fwww.oracle.com%2F; oraclelicense=accept-securebackup-cookie" "http://download.oracle.com/otn-pub/java/jdk/8u73-b02/jdk-8u73-linux-x64.rpm"
sudo yum -y localinstall jdk-8u73-linux-x64.rpm
rm -rf ~/jdk-8u*-linux-x64.rpm
export JAVA_HOME=/usr/java/jdk1.8.0_60/jre
echo "export JAVA_HOME=/usr/java/jdk1.8.0_60/jre" >> /etc/profile

####################### Logstash #######################
sudo rpm --import https://packages.elasticsearch.org/GPG-KEY-elasticsearch
echo '[logstash-2.1]
name=Logstash repository for 2.1.x packages
baseurl=https://packages.elastic.co/logstash/2.1/centos
gpgcheck=1
gpgkey=https://packages.elastic.co/GPG-KEY-elasticsearch
enabled=1
' | tee /etc/yum.repos.d/logstash.repo
yum install logstash -y

git clone https://github.com/wazuh/wazuh
cp ~/ossec_tmp/ossec-wazuh/extensions/logstash/01-ossec-singlehost.conf /etc/logstash/conf.d/
cp ~/ossec_tmp/ossec-wazuh/extensions/elasticsearch/elastic-ossec-template.json  /etc/logstash/

curl -O "http://geolite.maxmind.com/download/geoip/database/GeoLiteCity.dat.gz"
gzip -d GeoLiteCity.dat.gz && sudo mv GeoLiteCity.dat /etc/logstash/
usermod -a -G ossec logstash

####################### Install elasticsearch #######################
sudo rpm --import http://packages.elastic.co/GPG-KEY-elasticsearch
echo '[elasticsearch-2.x]
name=Elasticsearch repository for 2.x packages
baseurl=http://packages.elastic.co/elasticsearch/2.x/centos
gpgcheck=1
gpgkey=http://packages.elastic.co/GPG-KEY-elasticsearch
enabled=1
' | sudo tee /etc/yum.repos.d/elasticsearch.repo

yum -y install elasticsearch
sed -i 's/# network.host: 192.168.0.1/network.host: localhost/g' /etc/elasticsearch/elasticsearch.yml
sed -i 's/# cluster.name: my-application/cluster.name: ossec/g' /etc/elasticsearch/elasticsearch.yml
sed -i 's/# node.name: node-1/node.name: ossec_node1/g' /etc/elasticsearch/elasticsearch.yml
echo "index.number_of_shards: 1
index.number_of_replicas: 0
" >> /etc/elasticsearch/elasticsearch.yml
sudo systemctl start elasticsearch
sudo systemctl enable elasticsearch

curl -XGET localhost:9200
curl -XGET 'http://localhost:9200/_cluster/health?pretty=true'

cd ossec_tmp/ossec-wazuh/extensions/elasticsearch/ && curl -XPUT "http://localhost:9200/_template/ossec/" -d "@elastic-ossec-template.json"
systemctl start logstash

####################### Install Kibana #######################
sudo rpm --import https://packages.elastic.co/GPG-KEY-elasticsearch
echo '[kibana-4.4]
name=Kibana repository for 4.4.x packages
baseurl=http://packages.elastic.co/kibana/4.4/centos
gpgcheck=1
gpgkey=http://packages.elastic.co/GPG-KEY-elasticsearch
enabled=1
' | tee /etc/yum.repos.d/kibana.repo
yum -y install kibana
sed -i 's/# server.host: "0.0.0.0"/server.host: "localhost"/g' /opt/kibana/config/kibana.yml
systemctl enable kibana
systemctl start kibana


####################### Install nginx and Let's Encrypt #######################
yum -y install epel-release
yum -y install nginx httpd-tools
yum install certbot -y
htpasswd -c /etc/nginx/htpasswd.users kibanaadmin

cp /etc/nginx/nginx.conf /etc/nginx/nginx.conf.bak
echo '# For more information on configuration, see:
#   * Official English Documentation: http://nginx.org/en/docs/
#   * Official Russian Documentation: http://nginx.org/ru/docs/

user nginx;
worker_processes auto;
error_log /var/log/nginx/error.log;
pid /run/nginx.pid;

# Load dynamic modules. See /usr/share/nginx/README.dynamic.
include /usr/share/nginx/modules/*.conf;

events {
    worker_connections 1024;
}

http {
    log_format  main  '\$remote_addr - \$remote_user [\$time_local] "\$request" '
                      '\$status \$body_bytes_sent "\$http_referer" '
                      '"\$http_user_agent" "\$http_x_forwarded_for"';

    access_log  /var/log/nginx/access.log  main;

    sendfile            on;
    tcp_nopush          on;
    tcp_nodelay         on;
    keepalive_timeout   65;
    types_hash_max_size 2048;

    include             /etc/nginx/mime.types;
    default_type        application/octet-stream;

    # Load modular configuration files from the /etc/nginx/conf.d directory.
    # See http://nginx.org/en/docs/ngx_core_module.html#include
    # for more information.
    include /etc/nginx/conf.d/*.conf;

}
' | tee /etc/nginx/nginx.conf

echo 'server {
  listen 80;
  location ~ /.well-known {
      allow all;
  }
}
' | tee /etc/nginx/conf.d/letsencrypt.conf

systemctl start nginx

read -p "Enter a domain to create SSL Cert: " domain
read -p "Enter 'l' for Let's Encrypt or 'o' for OpenSSL: " answer
mkdir /etc/nginx/ssl
if [[ $answer = l ]] ; then
  mkdir -p .well-known/acme-challenge
  certbot certonly -a webroot --webroot-path=/usr/share/nginx/html -d $domain
  openssl dhparam -out /etc/nginx/ssl/dhparam.pem 2048

  rm -rf /etc/nginx/conf.d/letsencrypt.conf

  echo "server {
      listen 443 ssl;

      server_name "$domain";

      ssl_certificate /etc/letsencrypt/live/"$domain"/fullchain.pem;
      ssl_certificate_key /etc/letsencrypt/live/"$domain"/privkey.pem;
      ssl_dhparam /etc/nginx/ssl/dhparam.pem;

      ssl_protocols TLSv1 TLSv1.1 TLSv1.2;
      ssl_prefer_server_ciphers on;
      ssl_ciphers 'EECDH+AESGCM:EDH+AESGCM:AES256+EECDH:AES256+EDH';
      ssl_session_timeout 1d;
      ssl_session_cache shared:SSL:50m;
      ssl_stapling on;
      ssl_stapling_verify on;
      add_header Strict-Transport-Security max-age=15768000;

      location ~ /.well-known {
          allow all;
      }

      auth_basic 'Restricted Access';
      auth_basic_user_file /etc/nginx/htpasswd.users;

      location / {
          proxy_pass http://localhost:5601;
          proxy_http_version 1.1;
          proxy_set_header Upgrade \$http_upgrade;
          proxy_set_header Connection 'upgrade';
          proxy_set_header Host \$host;
          proxy_cache_bypass \$http_upgrade;
      }
  }
  " | tee /etc/nginx/conf.d/kibana.conf
  systemctl enable nginx
  systemctl restart nginx
  setsebool -P httpd_can_network_connect 1

  echo "30 2 * * 1 /usr/bin/letsencrypt renew >> /var/log/le-renew.log
35 2 * * 1 /bin/systemctl reload nginx" >> /etc/crontab
  systemctl start crond


  ####################### Install logstash #######################
  echo '[logstash-2.2]
name=logstash repository for 2.2 packages
baseurl=http://packages.elasticsearch.org/logstash/2.2/centos
gpgcheck=1
gpgkey=http://packages.elasticsearch.org/GPG-KEY-elasticsearch
enabled=1
' | tee /etc/yum.repos.d/logstash.repo
  yum -y install logstash

else
  openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout /etc/nginx/ssl/nginx-selfsigned.key -out /etc/nginx/ssl/nginx-selfsigned.crt
  openssl dhparam -out /etc/nginx/ssl/dhparam.pem 2048

  rm -rf /etc/nginx/conf.d/letsencrypt.conf

  echo "server {
      listen 443 ssl;

      server_name _;

      ssl_certificate /etc/nginx/ssl/nginx-selfsigned.crt;
      ssl_certificate_key /etc/nginx/ssl/nginx-selfsigned.key;
      ssl_dhparam /etc/nginx/ssl/dhparam.pem;

      ssl_protocols TLSv1 TLSv1.1 TLSv1.2;
      ssl_prefer_server_ciphers on;
      ssl_ciphers 'EECDH+AESGCM:EDH+AESGCM:AES256+EECDH:AES256+EDH';
      ssl_session_timeout 1d;
      ssl_session_cache shared:SSL:50m;
      ssl_stapling on;
      ssl_stapling_verify on;
      add_header Strict-Transport-Security max-age=15768000;

      location ~ /.well-known {
          allow all;
      }

      auth_basic 'Restricted Access';
      auth_basic_user_file /etc/nginx/htpasswd.users;

      location / {
          proxy_pass http://localhost:5601;
          proxy_http_version 1.1;
          proxy_set_header Upgrade \$http_upgrade;
          proxy_set_header Connection 'upgrade';
          proxy_set_header Host \$host;
          proxy_cache_bypass \$http_upgrade;
      }
  }
  " | tee /etc/nginx/conf.d/kibana.conf
  systemctl enable nginx
  systemctl restart nginx
  setsebool -P httpd_can_network_connect 1

fi


####################### Setup FirewllD #######################
yum install firewalld -y
systemctl enable firewalld
systemctl start firewalld
firewall-cmd --zone=public --permanent --add-service=https
firewall-cmd --zone=public --permanent --add-service=ssh
firewall-cmd --permanent --zone=public --add-port=1514/udp
firewall-cmd --reload
