#!/bin/bash

set -x
set -e

################################### Dependencies ###################################
yum install -y wget vim epel-release

###################################### Install Java ######################################
cd ~
wget --no-cookies --no-check-certificate --header "Cookie: gpw_e24=http%3A%2F%2Fwww.oracle.com%2F; oraclelicense=accept-securebackup-cookie" "http://download.oracle.com/otn-pub/java/jdk/8u73-b02/jdk-8u73-linux-x64.rpm"
sudo yum -y localinstall jdk-8u73-linux-x64.rpm
rm ~/jdk-8u*-linux-x64.rpm


###################################### Install Elasticsearch ######################################
sudo rpm --import http://packages.elastic.co/GPG-KEY-elasticsearch
echo '[elasticsearch-2.x]
name=Elasticsearch repository for 2.x packages
baseurl=http://packages.elastic.co/elasticsearch/2.x/centos
gpgcheck=1
gpgkey=http://packages.elastic.co/GPG-KEY-elasticsearch
enabled=1
' | sudo tee /etc/yum.repos.d/elasticsearch.repo
sudo yum -y install elasticsearch

echo "network.host: localhost" >> /etc/elasticsearch/elasticsearch.yml
echo "script.disable_dynamic: false" >> /etc/elasticsearch/elasticsearch.yml
sudo systemctl enable elasticsearch
sudo systemctl start elasticsearch

###################################### Install Kibana ######################################
echo '[kibana-4.4]
name=Kibana repository for 4.4.x packages
baseurl=http://packages.elastic.co/kibana/4.4/centos
gpgcheck=1
gpgkey=http://packages.elastic.co/GPG-KEY-elasticsearch
enabled=1
' | sudo tee /etc/yum.repos.d/kibana.repo

sudo yum -y install kibana
sed -i 's/# server.host: "localhost"/server.host: "localhost"/g' /opt/kibana/config/kibana.yml
sudo systemctl start kibana
sudo chkconfig kibana on

###################################### Let's encrypt ######################################
sudo yum install certbot -y
echo 'server{
	location ~ /.well-known {
        	allow all;
	}
}
' | sudo tee /etc/nginx/conf.d/le-well-known.conf
sudo nginx -t
echo -n "Please enter your domain name to register [ENTER]: "
read domain

sudo certbot certonly -a webroot --webroot-path=/usr/share/nginx/html -d $domain
sudo ls -l /etc/letsencrypt/live/$domain
#generate diffie-hellman
sudo openssl dhparam -out /etc/ssl/certs/dhparam.pem 2048

#Setup auto-renewal
sudo certbot renew
systemctl start crond
echo '30 2 * * 1 /usr/bin/certbot renew >> /var/log/le-renew.log
35 2 * * 1 /usr/bin/systemctl reload nginx
' | sudo tee /var/spool/cron/root

###################################### Install nginx ######################################
sudo yum -y install nginx httpd-tools
sudo htpasswd -c /etc/nginx/htpasswd.users kibanaadmin
#backup of config
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
    log_format  main  '$remote_addr - $remote_user [$time_local] \"$request\" '
                      '$status $body_bytes_sent \"$http_referer\" '
                      '\"$http_user_agent\" \"$http_x_forwarded_for\"';

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
' > sudo tee /etc/nginx/nginx.conf

echo 'server {
    listen 80;
    return 301 https://$host$request_uri;
}

server {
    listen 443 ssl;

    server_name $domain;

    ssl_certificate /etc/letsencrypt/live/$domain/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/$domain/privkey.pem;

    ssl_protocols TLSv1 TLSv1.1 TLSv1.2;
    ssl_prefer_server_ciphers on;
    ssl_dhparam /etc/ssl/certs/dhparam.pem;
    ssl_ciphers 'ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:DHE-DSS-AES128-GCM-SHA256:kEDH+AESGCM:ECDHE-RSA-AES128-SHA256:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA:ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA:ECDHE-ECDSA-AES256-SHA:DHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA:DHE-DSS-AES128-SHA256:DHE-RSA-AES256-SHA256:DHE-DSS-AES256-SHA:DHE-RSA-AES256-SHA:AES128-GCM-SHA256:AES256-GCM-SHA384:AES128-SHA256:AES256-SHA256:AES128-SHA:AES256-SHA:AES:CAMELLIA:DES-CBC3-SHA:!aNULL:!eNULL:!EXPORT:!DES:!RC4:!MD5:!PSK:!aECDH:!EDH-DSS-DES-CBC3-SHA:!EDH-RSA-DES-CBC3-SHA:!KRB5-DES-CBC3-SHA';
    ssl_session_timeout 1d;
    ssl_session_cache shared:SSL:50m;
    ssl_stapling on;
    ssl_stapling_verify on;
    add_header Strict-Transport-Security max-age=15768000;

    auth_basic "Restricted Access";
    auth_basic_user_file /etc/nginx/htpasswd.users;

    location ~ /.well-known {
    	allow all;
    }

    location / {
        proxy_pass http://localhost:5601;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_cache_bypass $http_upgrade;
    }
}
' | sudo tee /etc/nginx/conf.d/kibana.conf

sudo setsebool -P httpd_can_network_connect 1
sudo systemctl start nginx
sudo systemctl enable nginx


###################################### Install logstash ######################################
echo '[logstash-2.2]
name=logstash repository for 2.2 packages
baseurl=http://packages.elasticsearch.org/logstash/2.2/centos
gpgcheck=1
gpgkey=http://packages.elasticsearch.org/GPG-KEY-elasticsearch
enabled=1
' | sudo tee /etc/yum.repos.d/logstash.repo
sudo yum -y install logstash

echo 'input {
  beats {
    port => 5044
    ssl => true
    ssl_certificate => "/etc/letsencrypt/live/$domain/fullchain.pem"
    ssl_key => "/etc/letsencrypt/live/$domain/privkey.pem"
  }
}
' | sudo tee /etc/logstash/conf.d/02-beats-input.conf

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
' | sudo tee /etc/logstash/conf.d/10-syslog-filter.conf

echo 'output {
  elasticsearch {
    hosts => ["localhost:9200"]
    sniffing => true
    manage_template => false
    index => "%{[@metadata][beat]}-%{+YYYY.MM.dd}"
    document_type => "%{[@metadata][type]}"
  }
}
' | sudo tee /etc/logstash/conf.d/30-elasticsearch-output.conf
sudo service logstash configtest
sudo systemctl restart logstash
sudo chkconfig logstash on


######################################## Load Kibana Dashboards ########################################
cd ~
curl -L -O https://download.elastic.co/beats/dashboards/beats-dashboards-1.1.0.zip
sudo yum -y install unzip
unzip beats-dashboards-*.zip
cd beats-dashboards-*
./load.sh
cd ~
curl -O https://gist.githubusercontent.com/thisismitch/3429023e8438cc25b86c/raw/d8c479e2a1adcea8b1fe86570e42abab0f10f364/filebeat-index-template.json
curl -XPUT 'http://localhost:9200/_template/filebeat?pretty' -d@filebeat-index-template.json
