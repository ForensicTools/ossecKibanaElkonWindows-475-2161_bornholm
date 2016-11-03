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

####################### Install Java #######################
cd ~
wget --no-cookies --no-check-certificate --header "Cookie: gpw_e24=http%3A%2F%2Fwww.oracle.com%2F; oraclelicense=accept-securebackup-cookie" "http://download.oracle.com/otn-pub/java/jdk/8u73-b02/jdk-8u73-linux-x64.rpm"
sudo yum -y localinstall jdk-8u73-linux-x64.rpm
rm ~/jdk-8u*-linux-x64.rpm

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
sudo systemctl start elasticsearch
sudo systemctl enable elasticsearch

####################### Install Kibana #######################
echo '[kibana-4.4]
name=Kibana repository for 4.4.x packages
baseurl=http://packages.elastic.co/kibana/4.4/centos
gpgcheck=1
gpgkey=http://packages.elastic.co/GPG-KEY-elasticsearch
enabled=1
' | tee /etc/yum.repos.d/kibana.repo
yum -y install kibana
sed -i 's/# server.host: "0.0.0.0"/server.host: "localhost"/g' /opt/kibana/config/kibana.yml
chkconfig kibana on
systemctl start kibana


####################### Install nginx and Let's Encrypt #######################
yum -y install epel-release
yum -y install nginx httpd-tools
yum install certbot -y
htpasswd -c /etc/nginx/htpasswd.users kibanaadmin

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

  ####################### Install logstash #######################
  echo '[logstash-2.2]
name=logstash repository for 2.2 packages
baseurl=http://packages.elasticsearch.org/logstash/2.2/centos
gpgcheck=1
gpgkey=http://packages.elasticsearch.org/GPG-KEY-elasticsearch
enabled=1
' | tee /etc/yum.repos.d/logstash.repo
  yum -y install logstash
fi

read -p "Enter a domain to create SSL Cert: " domain
cd /etc/pki/tls
sudo openssl req -subj '/'$domain'/' -x509 -days 3650 -batch -nodes -newkey rsa:2048 -keyout private/logstash-forwarder.key -out certs/logstash-forwarder.crt
echo 'input {
  beats {
    port => 5044
    ssl => true
    ssl_certificate => "/etc/pki/tls/certs/logstash-forwarder.crt"
    ssl_key => "/etc/pki/tls/private/logstash-forwarder.key"
  }
}
' | tee /etc/logstash/conf.d/02-beats-input.conf

echo 'filter {
  if [type] == "syslog" {
    grok {
      match => { "message" => "%{SYSLOGTIMESTAMP:syslog_timestamp} %{SYSLOGHOST:syslog_hostname} %{DATA:syslog_program}(?:\[%{POSINT:syslog_pid}\])?: %{GREEDYDATA:syslog_message}" }
      add_field => [ "received_at", "%{@timestamp}" ]
      add_field => [ "received_from", "%{host}" ]
    }
    syslog_pri { }
    date {
      match => [ "syslog_timestamp", "MMM  d HH:mm:ss", "MMM dd HH:mm:ss" ]
    }
  }
}
' | tee /etc/logstash/conf.d/10-syslog-filter.conf

echo 'output {
  elasticsearch {
    hosts => ["localhost:9200"]
    sniffing => true
    manage_template => false
    index => "%{[@metadata][beat]}-%{+YYYY.MM.dd}"
    document_type => "%{[@metadata][type]}"
  }
}
' | tee /etc/logstash/conf.d/30-elasticsearch-output.conf
service logstash configtest
systemctl restart logstash
chkconfig logstash on

####################### Load Kibana dashboards #######################
cd ~
curl -L -O https://download.elastic.co/beats/dashboards/beats-dashboards-1.1.0.zip
yum -y install unzip
unzip beats-dashboards-*.zip
cd beats-dashboards-*
./load.sh

####################### Filebeat index #######################
cd ~
curl -O https://gist.githubusercontent.com/thisismitch/3429023e8438cc25b86c/raw/d8c479e2a1adcea8b1fe86570e42abab0f10f364/filebeat-index-template.json
curl -XPUT 'http://localhost:9200/_template/filebeat?pretty' -d@filebeat-index-template.json

####################### Setup FirewllD #######################
yum install firewalld -y
systemctl enable firewalld
systemctl start firewalld
firewall-cmd --zone=public --permanent --add-service=https
firewall-cmd --zone=public --permanent --add-service=ssh
firewall-cmd --reload


#######################
echo "These are the index patterns that we just loaded:

[packetbeat-]YYYY.MM.DD
[topbeat-]YYYY.MM.DD
[filebeat-]YYYY.MM.DD
[winlogbeat-]YYYY.MM.DD
When we start using Kibana, we will select the Filebeat index pattern as our default.

"

