#!/bin/bash

#====================================================
#	System Request:Debian 7+/Ubuntu 15+/Centos 6+
#	Dscription: V2RAY 基于 CADDY 的 VMESS+H2|WS+TLS+Website(Use Host)+BBR
#	Official document: www.v2ray.com
#====================================================

#定义文字颜色
Green="\033[32m"
Red="\033[31m"
GreenBG="\033[42;37m"
RedBG="\033[41;37m"
Font="\033[0m"

#定义提示信息
Info="${Green}[信息]${Font}"
OK="${Green}[OK]${Font}"
Error="${Red}[错误]${Font}"

#定义配置文件路径
v2ray_conf_dir="/etc/v2ray"
v2ray_conf_file="${v2ray_conf_dir}/config.json"
v2ray_conf_client="${v2ray_conf_dir}/client.json"
v2ray_script_dir="/root/v2ray_install_script"
v2ray_win_client_dir="/root/v2ray_win_client"
caddy_conf_dir="/etc/caddy"
caddy_conf_file="${caddy_conf_dir}/Caddyfile"
caddy_cert_dir="/etc/ssl/caddy"
caddy_log_dir="/var/log/caddy"
caddy_bin_file="/usr/local/bin/caddy"
www_dir="/var/www"
tls_cert_mail="pisces562@gmail.com"

source /etc/os-release

# show up level function name
show_fun_name(){
	echo "==> runing ${FUNCNAME[1]}"
}

#脚本欢迎语
v2ray_hello(){
	echo ""
	echo -e "${Info} ${GreenBG} 你正在执行 V2RAY 基于 CADDY 的 VMESS+H2|WS+TLS+Website(Use Host)+BBR 一键安装脚本 ${Font}"
	echo ""
	random_number
}

#生成 转发端口 UUID 随机路径 伪装域名
random_number(){
	let v2ray_port=19840
#	let v2ray_port=$RANDOM+10000
	UUID=$(cat /proc/sys/kernel/random/uuid)
#	v2raypath=$(cat /dev/urandom | head -n 10 | md5sum | head -c 8)
	v2raypath=clndl562
#	web_download_path="dl/$(cat /dev/urandom | head -n 10 | md5sum | head -c 8)"
  web_download_path="dl/clndl562"
}

#检测root权限
is_root(){
	if [ $(id -u) -eq 0 ]
		then echo -e "${OK} ${GreenBG} 当前用户是root用户，开始安装流程 ${Font}"
		sleep 3
	else
		echo -e "${Error} ${RedBG} 当前用户不是root用户，请切换到root用户后重新执行脚本 ${Font}"
		exit 1
	fi
}

#检测系统版本
check_system(){
	VERSION=`echo ${VERSION} | awk -F "[()]" '{print $2}'`
	if [[ "${ID}" == "centos" && ${VERSION_ID} -ge 7 ]];then
		echo -e "${OK} ${GreenBG} 当前系统为 Centos ${VERSION_ID} ${VERSION} ${Font}"
		INS="yum"
		echo -e "${OK} ${GreenBG} SElinux 设置中，请耐心等待，不要进行其他操作${Font}"
		setsebool -P httpd_can_network_connect 1 >/dev/null 2>&1
		echo -e "${OK} ${GreenBG} SElinux 设置完成 ${Font}"
	elif [[ "${ID}" == "debian" && ${VERSION_ID} -ge 8 ]];then
		echo -e "${OK} ${GreenBG} 当前系统为 Debian ${VERSION_ID} ${VERSION} ${Font}"
		INS="apt"
	elif [[ "${ID}" == "ubuntu" && `echo "${VERSION_ID}" | cut -d '.' -f1` -ge 16 ]];then
		echo -e "${OK} ${GreenBG} 当前系统为 Ubuntu ${VERSION_ID} ${VERSION_CODENAME} ${Font}"
		INS="apt"
	else
		echo -e "${Error} ${RedBG} 当前系统为 ${ID} ${VERSION_ID} 不在支持的系统列表内，安装中断 ${Font}"
		exit 1
	fi
}

#检测安装完成或失败
judge(){
	if [[ $? -eq 0 ]];then
		echo -e "${OK} ${GreenBG} $1 完成 ${Font}"
		sleep 1
	else
		echo -e "${Error} ${RedBG} $1 失败 ${Font}"
		exit 1
	fi
}

#用户设定 域名 端口 alterID
port_alterid_set(){
	echo -e "${Info} ${GreenBG} 【配置 1/4 】请输入你的域名信息(如:www.bing.com)，请确保域名A记录已正确解析至服务器IP ${Font}"
#	stty erase '^H' && read -p "请输入：" domain
	read -p "请输入：" domain

	echo -e "${Info} ${GreenBG} 【配置 2/4 】请输入连接端口（默认:443 无特殊需求请直接按回车键） ${Font}"
#	stty erase '^H' && read -p "请输入：" caddy_port
	read -p "请输入：" caddy_port
	[[ -z ${caddy_port} ]] && caddy_port="443"

	echo -e "${Info} ${GreenBG} 【配置 3/4 】请输入alterID（默认:64 无特殊需求请直接按回车键） ${Font}"
#	stty erase '^H' && read -p "请输入：" alterID
	read -p "请输入：" alterID
	[[ -z ${alterID} ]] && alterID="64"

	echo -e "${Info} ${GreenBG} 【配置 4/4 】请输入 Protocol Mode(h2 or websocket)（默认:h2, 可输入 h2 或者 ws） ${Font}"
	while :; do
  	read -p "请输入(h2或者ws或者直接回车)：" h2_or_ws
  	case ${h2_or_ws} in
  		h2|ws)
  			break
  			;;
  		"")
  			h2_or_ws=h2
  			break
  			;;
  		*)
  			echo -e "only h2 or ws is accepted"
  	esac
	done

	echo -e "----------------------------------------------------------"
	echo -e "${Info} ${GreenBG} 你输入的配置信息为 域名：${domain} 端口：${port} alterID：${alterID} ${Font}"
	echo -e "----------------------------------------------------------"
	# define root of webpage
	website_dir=${www_dir}/${domain}
}

#强制清除可能残余的http服务 v2ray服务 关闭防火墙 更新源
apache_uninstall(){
	echo -e "${OK} ${GreenBG} 正在强制清理可能残余的http服务 ${Font}"
	if [[ "${ID}" == "centos" ]];then

		systemctl disable httpd >/dev/null 2>&1
		systemctl stop httpd >/dev/null 2>&1
		yum erase httpd httpd-tools apr apr-util -y >/dev/null 2>&1

		systemctl disable firewalld >/dev/null 2>&1
		systemctl stop firewalld >/dev/null 2>&1

		echo -e "${OK} ${GreenBG} 正在更新系统 请稍后 …… ${Font}"

		yum -y update

	else

		systemctl disable apache2 >/dev/null 2>&1
		systemctl stop apache2 >/dev/null 2>&1
		apt purge apache2 -y >/dev/null 2>&1

		echo -e "${OK} ${GreenBG} 正在更新系统 请稍后 …… ${Font}"

		apt -y update

	fi

	systemctl disable caddy >/dev/null 2>&1
	systemctl stop caddy >/dev/null 2>&1

	systemctl disable v2ray >/dev/null 2>&1
	systemctl stop v2ray >/dev/null 2>&1
	killall -9 v2ray >/dev/null 2>&1

	systemctl disable rinetd-bbr >/dev/null 2>&1
	systemctl stop rinetd-bbr >/dev/null 2>&1
	killall -9 rinetd-bbr >/dev/null 2>&1

	rm -rf ${caddy_bin_file} ${caddy_conf_dir} ${caddy_cert_dir} /etc/systemd/system/caddy.service >/dev/null 2>&1
	rm -rf ${v2ray_conf_dir} /etc/systemd/system/v2ray.service >/dev/null 2>&1
	rm -rf /usr/bin/rinetd-bbr /etc/rinetd-bbr.conf /etc/systemd/system/rinetd-bbr.service >/dev/null 2>&1
	rm -rf ${website_dir} >/dev/null 2>&1
}

#安装各种依赖工具
dependency_install(){
	for CMD in iptables grep cut xargs systemctl ip awk
	do
		if ! type -p ${CMD}; then
			echo -e "${Error} ${RedBG} 缺少必要依赖 脚本终止安装 ${Font}"
			exit 1
		fi
	done
	${INS} install curl lsof unzip zip -y

# libcap is used to enable command setcap allowing caddy bind privileged ports (e.g. 80,443) as a non-root user
	if [[ "${ID}" == "centos" ]];then
		${INS} -y install crontabs libcap
	else
		${INS} -y install cron libcap2-bin
	fi
	judge "安装 crontab 和 setcap"

}

#检测域名解析是否正确
domain_check(){
	domain_ip=`ping ${domain} -c 1 | sed '1{s/[^(]*(//;s/).*//;q}'`
	echo -e "${OK} ${GreenBG} 正在获取 公网ip 信息，请耐心等待 ${Font}"
	local_ip=`curl -4 ip.sb`
	echo -e "${OK} ${GreenBG} 域名dns解析IP：${domain_ip} ${Font}"
	echo -e "${OK} ${GreenBG} 本机IP: ${local_ip} ${Font}"
	sleep 2
	if [[ ${local_ip} = ${domain_ip} ]];then
		echo -e "${OK} ${GreenBG} 域名dns解析IP  与 本机IP 匹配 域名解析正确 ${Font}"
		sleep 2
	else
		echo -e "${Error} ${RedBG} 域名dns解析IP 与 本机IP 不匹配 是否继续安装？（y/n）${Font}" && read install
		case $install in
		[yY][eE][sS]|[yY])
			echo -e "${GreenBG} 继续安装 ${Font}"
			sleep 2
			;;
		*)
			echo -e "${RedBG} 安装终止 ${Font}"
			exit 2
			;;
		esac
	fi
}

#检测端口是否占用
port_exist_check(){
	if [[ 0 -eq `lsof -i:"$1" | wc -l` ]];then
		echo -e "${OK} ${GreenBG} $1 端口未被占用 ${Font}"
		sleep 1
	else
		echo -e "${Error} ${RedBG} 检测到 $1 端口被占用，以下为 $1 端口占用信息 ${Font}"
		lsof -i:"$1"
		echo -e "${OK} ${GreenBG} 5s 后将尝试自动 kill 占用进程 ${Font}"
		sleep 5
		lsof -i:"$1" | awk '{print $2}'| grep -v "PID" | xargs kill -9
		echo -e "${OK} ${GreenBG} kill 完成 ${Font}"
		sleep 1
	fi
}

#同步服务器时间
time_modify(){

	${INS} install ntpdate -y
	judge "安装 NTPdate 时间同步服务 "

	systemctl stop ntp &>/dev/null

	echo -e "${Info} ${GreenBG} 正在进行时间同步 ${Font}"
	ntpdate time.nist.gov

	if [[ $? -eq 0 ]];then 
		echo -e "${OK} ${GreenBG} 时间同步成功 ${Font}"
		echo -e "${OK} ${GreenBG} 当前系统时间 `date -R`（时区时间换算后误差应为三分钟以内）${Font}"
		sleep 1
	else
		echo -e "${Error} ${RedBG} 时间同步失败，请检查ntpdate服务是否正常工作 ${Font}"
	fi 
}

#安装v2ray主程序
v2ray_install(){
	if [[ -d ${v2ray_script_dir} ]];then
		rm -rf ${v2ray_script_dir}
	fi

	mkdir -p ${v2ray_script_dir} && cd ${v2ray_script_dir}
	wget -O go.sh https://raw.githubusercontent.com/RoHBg/v2ray/master/script/install_v2ray.sh
#	wget -N --no-check-certificate https://install.direct/go.sh
	
	if [[ -f go.sh ]];then
		bash go.sh --force
		judge "安装 V2ray"
	else
		echo -e "${Error} ${RedBG} V2ray 安装文件下载失败，请检查下载地址是否可用 ${Font}"
		exit 4
	fi
}

#设置定时升级任务
modify_crontab(){
	echo -e "${OK} ${GreenBG} 配置每天凌晨自动升级V2ray内核任务 ${Font}"
	sleep 2
	#crontab -l >> crontab.txt
	echo "20 12 * * * bash ${v2ray_script_dir}/go.sh | tee -a ${v2ray_script_dir}/update.log" >> crontab.txt
	echo "30 12 * * * /sbin/reboot" >> crontab.txt
	crontab crontab.txt
	sleep 2
	if [[ "${ID}" == "centos" ]];then
		systemctl restart crond
	else
		systemctl restart cron
	fi
	rm -f crontab.txt
}

#安装caddy主程序
caddy_install(){
	curl https://raw.githubusercontent.com/RoHBg/v2ray/master/script/install_caddy.sh | bash -s personal
#	curl https://getcaddy.com | bash -s personal

	chown root:root ${caddy_bin_file}
	chmod 755 ${caddy_bin_file}

	# Give the caddy binary the ability to bind to privileged ports (e.g. 80, 443) as a non-root user:
	setcap 'cap_net_bind_service=+ep' ${caddy_bin_file}

	# create account www-data if id doesn't exist
	id www-data
	if [[ $? -ne 0 ]]; then
		groupadd -g 33 www-data
		useradd \
		  -g www-data --no-user-group \
		  --home-dir ${www_dir} --no-create-home \
		  --shell /usr/sbin/nologin \
		  --system --uid 33 www-data
	fi

	mkdir ${caddy_conf_dir}/
	chown -R root:root ${caddy_conf_dir}/
	mkdir -p ${caddy_cert_dir}
	chown -R root:www-data ${caddy_cert_dir}
	chown -R www-data:www-data ${caddy_cert_dir}/*
	chmod 0770 ${caddy_cert_dir}

	# Create the home directory for the server and give it appropriate ownership and permissions:
	mkdir ${www_dir}/${domain}
	chown www-data:www-data ${www_dir}
	chmod 555 ${www_dir}
	chown -R www-data:www-data ${www_dir}/${domain}
	chmod -R 555 ${www_dir}/${domain}

	# Install the systemd service unit configuration file, reload the systemd daemon, and start caddy:
#	wget https://raw.githubusercontent.com/caddyserver/caddy/master/dist/init/linux-systemd/caddy.service
#	cp caddy.service /etc/systemd/system/
#	rm -f caddy.service

	touch /etc/systemd/system/caddy.service

#	cat <<EOF > /etc/systemd/system/caddy.service
#[Unit]
#Description=Caddy server
#[Service]
#ExecStart=${caddy_bin_file} -conf=${caddy_conf_dir}/Caddyfile -agree=true -ca=https://acme-v02.api.letsencrypt.org/directory
#Restart=always
#User=root
#[Install]
#WantedBy=multi-user.target
#EOF


	cat <<EOF > /etc/systemd/system/caddy.service
[Unit]
Description=Caddy HTTP/2 web server
Documentation=https://caddyserver.com/docs
After=network-online.target
Wants=network-online.target systemd-networkd-wait-online.service

[Service]
Restart=on-abnormal

; User and group the process will run as.
User=www-data
Group=www-data

; Letsencrypt-issued certificates will be written to this directory.
Environment=CADDYPATH=${caddy_cert_dir}

; Always set "-root" to something safe in case it gets forgotten in the Caddyfile.
ExecStart=${caddy_bin_file} -log stdout -agree=true -conf=${caddy_conf_dir}/Caddyfile -root=/var/tmp
ExecReload=/bin/kill -USR1 $MAINPID

; Use graceful shutdown with a reasonable timeout
KillMode=mixed
KillSignal=SIGQUIT
TimeoutStopSec=5s

; Limit the number of file descriptors; see (man systemd.exec) for more limit settings.
LimitNOFILE=1048576
; Unmodified caddy is not expected to use more than that.
LimitNPROC=512

; Use private /tmp and /var/tmp, which are discarded after caddy stops.
PrivateTmp=true
; Use a minimal /dev (May bring additional security if switched to 'true', but it may not work on Raspberry Pi's or other devices, so it has been disabled in this dist.)
PrivateDevices=false
; Hide /home, /root, and /run/user. Nobody will steal your SSH-keys.
ProtectHome=true
; Make /usr, /boot, /etc and possibly some more folders read-only.
ProtectSystem=full
; … except /etc/ssl/caddy, because we want Letsencrypt-certificates there.
;   This merely retains r/w access rights, it does not add any new. Must still be writable on the host!
ReadWriteDirectories=/etc/ssl/caddy

; The following additional security directives only work with systemd v229 or later.
; They further restrict privileges that can be gained by caddy. Uncomment if you like.
; Note that you may have to add capabilities required by any plugins in use.
;CapabilityBoundingSet=CAP_NET_BIND_SERVICE
;AmbientCapabilities=CAP_NET_BIND_SERVICE
;NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
EOF

	judge "caddy 安装"

	chown root:root /etc/systemd/system/caddy.service
	chmod 644 /etc/systemd/system/caddy.service
	systemctl daemon-reload

}

#安装web伪装站点
web_install(){
	echo -e "${OK} ${GreenBG} 安装Website伪装站点 ${Font}"
	mkdir -p ${website_dir}
	wget https://github.com/dylanbai8/V2Ray_h2-tls_Website_onekey/raw/master/V2rayWebsite.tar.gz
	tar -zxvf V2rayWebsite.tar.gz -C ${website_dir}
	rm -f V2rayWebsite.tar.gz
}

#生成v2ray配置文件
v2ray_conf_create(){
	touch ${v2ray_conf_file}
	
	if [[ ${h2_or_ws} = "h2" ]]; then
		echo -e "${Info} ${GreenBG} Creating v2ray conf for ** h2 ** protocol... ${Font}"
		cat <<EOF > ${v2ray_conf_file}
{
  "log": {
    "loglevel": "info",
    "access": "/var/log/v2ray/access.log",
    "error": "/var/log/v2ray/error.log"
  },
  "inbounds": [{
    "port": ${v2ray_port},
    "listen": "127.0.0.1",
    "protocol": "vmess",
    "settings": {
      "clients": [
        {
          "id": "${UUID}",
          "level": 1,
          "alterId": ${alterID}
        }
      ]
    },
    "streamSettings": {
      "network": "h2",
      "httpSettings": {
        "host": ["${domain}"],
        "path": "/${v2raypath}"
      },
      "security": "tls",
      "tlsSettings": {
        "certificates": [
          {
            "certificateFile": "${caddy_cert_dir}/acme/acme-v02.api.letsencrypt.org/sites/${domain}/${domain}.crt",
            "keyFile": "${caddy_cert_dir}/acme/acme-v02.api.letsencrypt.org/sites/${domain}/${domain}.key"
          }
        ]
      }
    }
  }],
  "outbounds": [{
    "protocol": "freedom",
    "settings": {}
  },{
    "protocol": "blackhole",
    "settings": {},
    "tag": "blocked"
  }],
  "routing": {
    "rules": [
     {
         "type": "field",
         "protocol": ["bittorrent"],
         "outboundTag": "blocked"
     },
      {
        "type": "field",
        "ip": ["geoip:private"],
        "outboundTag": "blocked"
      }
    ]
  }
}
EOF

	elif [[ ${h2_or_ws} = "ws" ]]; then
		echo -e "${Info} ${GreenBG} Creating v2ray conf for ** websocket ** protocol... ${Font}"
		cat <<EOF > ${v2ray_conf_file}	
{
  "log": {
    "loglevel": "info",
    "access": "/var/log/v2ray/access.log",
    "error": "/var/log/v2ray/error.log"
  },
  "inbounds": [{
    "port": ${v2ray_port},
    "listen": "127.0.0.1",
    "protocol": "vmess",
    "settings": {
      "clients": [
        {
          "id": "${UUID}",
          "level": 1,
          "alterId": ${alterID}
        }
      ]
    },
    "streamSettings": {
      "network": "ws",
      "wsSettings": {
        "path": "/${v2raypath}"
      }
    }
  }],
  "outbounds": [{
    "protocol": "freedom",
    "settings": {}
  },{
    "protocol": "blackhole",
    "settings": {},
    "tag": "blocked"
  }],
  "routing": {
    "rules": [
     {
         "type": "field",
         "protocol": ["bittorrent"],
         "outboundTag": "blocked"
     },
      {
        "type": "field",
        "ip": ["geoip:private"],
        "outboundTag": "blocked"
      }
    ]
  }
}
EOF

	else
		echo -e "${Error} ${RedBG} Protocol mode ${h2_or_ws} isn't supported ${Font}"
	fi

#	modify_port_UUID
	judge "V2ray 配置"
}

#生成caddy配置文件
caddy_conf_create(){
	mkdir ${caddy_conf_dir}
	touch ${caddy_conf_dir}/Caddyfile

	if [[ ${h2_or_ws} = "h2" ]]; then
		echo -e "${Info} ${GreenBG} Creating Caddy conf for ** h2 ** protocol... ${Font}"
		cat <<EOF > ${caddy_conf_dir}/Caddyfile
${domain}:${caddy_port} {

    gzip
    root ${website_dir}/
    tls ${tls_cert_mail}
    log ${caddy_log_dir}/${domain}.log
    
    proxy /${v2raypath} https://localhost:${v2ray_port} {
         header_upstream Host "${domain}"
         header_upstream X-Forwarded-Proto "https"
         insecure_skip_verify
    }

    header / {
        Strict-Transport-Security "max-age=31536000;"
        X-XSS-Protection "1; mode=block"
        X-Content-Type-Options "nosniff"
        X-Frame-Options "DENY"
    }
	
}
EOF

	elif [[ ${h2_or_ws} = "ws" ]]; then
		echo -e "${Info} ${GreenBG} Creating Caddy conf for ** websocket ** protocol... ${Font}"
		cat <<EOF > ${caddy_conf_dir}/Caddyfile
${domain}:${caddy_port} {

    gzip
    root ${website_dir}/
    tls ${tls_cert_mail}
    log ${caddy_log_dir}/${domain}.log
    
    proxy /${v2raypath} localhost:${v2ray_port} {
        websocket
        header_upstream -Origin
    }
	
}
EOF
	
	else
		echo -e "${Error} ${RedBG} Protocol mode ${h2_or_ws} isn't supported ${Font}"
	fi

#	modify_caddy
	judge "caddy 配置"

	# create caddy log file
	mkdir ${caddy_log_dir}
	chown -R www-data:www-data ${caddy_log_dir}
	systemctl start caddy
}

#生成客户端json文件
v2ray_client_config_create(){
	touch ${v2ray_conf_client}
	cat <<EOF > ${v2ray_conf_client}
{
  "log": {
    "loglevel": "info",
    "access": "",
    "error": ""
  },
  "dns": {
    "servers": [
      "8.8.8.8",
      "1.1.1.1",
      "119.29.29.29",
      "114.114.114.114"
    ]
  },
  "inbound": {
    "port": 1087,
    "listen": "127.0.0.1",
    "protocol": "http",
    "settings": {
      "timeout": 360
    }
  },
  "inboundDetour": [
    {
      "port": 1080,
      "listen": "127.0.0.1",
      "protocol": "socks",
      "settings": {
        "auth": "noauth",
        "timeout": 360,
        "udp": true
      }
    }
  ],
  "outbound": {
    "tag": "agentout",
    "protocol": "vmess",
    "streamSettings": {
      "network": "h2",
      "httpSettings": {
        "host": [
          "${domain}"
        ],
        "path": "/${v2raypath}"
      },
      "tlsSettings": {},
      "security": "tls"
    },
    "settings": {
      "vnext": [
        {
          "users": [
            {
              "alterId": ${alterID},
              "id": "${UUID}"
            }
          ],
          "port": ${caddy_port},
          "address": "${domain}"
        }
      ]
    }
  },
  "outboundDetour": [
    {
      "tag": "direct",
      "protocol": "freedom",
      "settings": {
        "response": null
      }
    },
    {
      "tag": "blockout",
      "protocol": "blackhole",
      "settings": {
        "response": {
          "type": "http"
        }
      }
    }
  ],
  "routing": {
    "strategy": "rules",
    "settings": {
      "domainStrategy": "IPIfNonMatch",
      "rules": [
        {
          "type": "field",
          "outboundTag": "direct",
          "ip": [
            "geoip:private"
          ]
        },
        {
          "type": "field",
          "outboundTag": "direct",
          "domain": [
            "geosite:cn"
          ]
        },
        {
          "type": "field",
          "outboundTag": "direct",
          "ip": [
            "geoip:cn"
          ]
        }
      ]
    }
  }
}
EOF

#	modify_clientjson

	rm -rf ${website_dir}/${web_download_path}
	mkdir -p ${website_dir}/${web_download_path}
	cp -rp ${v2ray_conf_client} ${website_dir}/${web_download_path}/config.json
	chmod -R 555 ${website_dir}/${web_download_path}

	judge "客户端json配置"
}

#修正v2ray配置文件
#modify_port_UUID(){
#	sed -i "s/SETPORTV/${v2ray_port}/g" "${v2ray_conf_file}"
#	sed -i "s/SETUUID/${UUID}/g" "${v2ray_conf_file}"
#	sed -i "s/SETALTERID/${alterID}/g" "${v2ray_conf_file}"
#	sed -i "s/SETPATH/${v2raypath}/g" "${v2ray_conf_file}"
#	sed -i "s/SETSERVER/${domain}/g" "${v2ray_conf_file}"
#}

#修正caddy配置配置文件
#modify_caddy(){
#	sed -i "s/SETPORT443/${caddy_port}/g" "${caddy_conf_file}"
#	sed -i "s/SETPORTV/${v2ray_port}/g" "${caddy_conf_file}"
#	sed -i "s/SETPATH/${v2raypath}/g" "${caddy_conf_file}"
#	sed -i "s/SETSERVER/${domain}/g" "${caddy_conf_file}"
#}

#修正客户端json配置文件
#modify_clientjson(){
#	sed -i "s/SETSERVER/${domain}/g" "${v2ray_conf_client}"
#	sed -i "s/SETPORT443/${caddy_port}/g" "${v2ray_conf_client}"
#	sed -i "s/SETUUID/${UUID}/g" "${v2ray_conf_client}"
#	sed -i "s/SETALTERID/${alterID}/g" "${v2ray_conf_client}"
#	sed -i "s/SETPATH/${v2raypath}/g" "${v2ray_conf_client}"
#}

#安装bbr端口加速
enable_bbr(){
	grep -q 'net.core.default_qdisc=fq' /etc/sysctl.conf
	if [ $? -ne 0 ]; then
		echo "net.core.default_qdisc=fq" >> /etc/sysctl.conf
		sysctl -p
	fi

	grep -q 'net.ipv4.tcp_congestion_control=bbr' /etc/sysctl.conf
	if [ $? -ne 0 ]; then
		echo "net.ipv4.tcp_congestion_control=bbr" >> /etc/sysctl.conf
		sysctl -p
	fi

	lsmod | grep bbr
	judge "enable bbr"

}

#检查ssl证书是否生成
check_ssl(){
	echo -e "${OK} ${GreenBG} 正在等待域名证书生成 ${Font}"
	sleep 15
if [[ -e ${caddy_cert_dir}/acme/acme-v02.api.letsencrypt.org/sites/${domain}/${domain}.key ]]; then
	echo -e "${OK} ${GreenBG} SSL证书申请 成功 ${Font}"
else
	echo -e "${Error} ${RedBG} SSL证书申请 失败 请确认是否超出Let’s Encrypt申请次数或检查服务器网络 ${Font}"
	echo -e "${Error} ${RedBG} 注意：证书每个IP每3小时10次 7天内每个子域名不超过5次总计不超过20次 ${Font}"
	exit 1
fi
}

#重启caddy和v2ray程序 加载配置
start_process_systemd(){
	systemctl enable v2ray >/dev/null 2>&1
	systemctl enable caddy >/dev/null 2>&1

	systemctl restart caddy
	judge "caddy 启动"

	systemctl restart v2ray
	judge "V2ray 启动"
}

#展示客户端配置信息
show_information(){
#	clear
	echo ""
	echo -e "${Info} ${GreenBG} V2RAY 基于 CADDY 的 VMESS+${h2_or_ws}+TLS+Website(Use Host)+BBR 安装成功 ${Font}"
	echo -e "----------------------------------------------------------"
	echo -e "${Green} 【您的 V2ray 配置信息】 ${Font}"
	echo -e "${Green} 地址（address）：${Font} ${domain}"
	echo -e "${Green} 端口（port）：${Font} ${caddy_port}"
	echo -e "${Green} 用户id（UUID）：${Font} ${UUID}"
	echo -e "${Green} 额外id（alterId）：${Font} ${alterID}"
	echo -e "${Green} 加密方式（security）：${Font} 自适应（建议 none）"
	echo -e "${Green} 传输协议（network）：${Font} ${h2_or_ws}"
	echo -e "${Green} 伪装类型（type）：${Font} none "
	echo -e "${Green} WS 路径（ws  path）（Path）（WebSocket 路径）：${Font} /${v2raypath} "
	echo -e "${Green} WS Host（伪装域名）（Host）：${Font} ${domain}"
	echo -e "${Green} HTTP头（适用于 BifrostV）：${Font} 字段名：host 值：${domain}"
	echo -e "${Green} Mux 多路复用：${Font} 自适应"
	echo -e "${Green} 底层传输安全（加密方式）：${Font} tls"
	if [ "${caddy_port}" -eq "443" ];then
	echo -e "${Green} Website 伪装站点：${Font} https://${domain}"
	echo -e "${Green} 客户端配置文件下载地址（URL）：${Font} https://${domain}/${web_download_path}/config.json ${Green} ${Font}"
	echo -e "${Green} Windows 客户端（已打包 config 即下即用） ：${Font} https://${domain}/${web_download_path}/v2rayN-win.zip ${Green} ${Font}"
	else
	echo -e "${Green} Website 伪装站点：${Font} https://${domain}:${caddy_port}"
	echo -e "${Green} 客户端配置文件下载地址（URL）：${Font} https://${domain}:${caddy_port}/${web_download_path}/config.json ${Green} ${Font}"
	echo -e "${Green} Windows 客户端（已打包 config 即下即用） ：${Font} https://${domain}:${caddy_port}/${web_download_path}/v2rayN-win.zip ${Green} ${Font}"
	fi
	echo -e "----------------------------------------------------------"
}

#命令块执行列表
main(){
	is_root
	check_system
	v2ray_hello
	port_alterid_set
	apache_uninstall
	dependency_install
	domain_check
	port_exist_check 80
	port_exist_check ${caddy_port}
	time_modify
	v2ray_install
#	modify_crontab
	caddy_install
#	web_install
	v2ray_conf_create
	caddy_conf_create
#	v2ray_client_config_create
	enable_bbr
#	win64_v2ray
	check_ssl
	show_information
	start_process_systemd
}

#删除website客户端配置文件 防止被抓取
rm_userjson(){
	rm -rf ${website_dir}/${web_download_path}
	echo -e "${OK} ${GreenBG} 客户端配置文件 config.json 已从 Website 中删除 ${Font}"
	echo -e "${OK} ${GreenBG} 提示：如果忘记配置信息 可执行 bash h.sh -n 重新生成 ${Font}"
}

#生成新的UUID并重启服务
new_uuid(){
if [[ -e ${website_dir}/index.bak ]]; then
	echo -e "${Info} ${GreenBG} 您已开启账号分享功能，无法手动更换 UUID 和生成 config.json 配置文件 ${Font}"
	echo -e "${Info} ${GreenBG} 提示：紧急更换共享 UUID 请执行 bash h.sh -m ${Font}"
else
	random_number
	sed -i "/\"id\"/c \\\t\t\t\t\t\"id\":\"${UUID}\"" ${v2ray_conf_file}
	sed -i "/\"id\"/c \\\t\t\t\t\t\t\t\"id\":\"${UUID}\"" ${v2ray_conf_client}
	rm -rf ${website_dir}/${web_download_path}
	mkdir -p ${website_dir}/${web_download_path}
	cp -rp ${v2ray_conf_client} ${website_dir}/${web_download_path}/config.json
	win64_v2ray
	systemctl restart v2ray
	judge "重启V2ray进程载入新的配置文件"
	echo -e "${OK} ${GreenBG} 新的 用户id（UUID）: ${UUID} ${Font}"
	echo -e "${OK} ${GreenBG} 新的 客户端配置文件下载地址（URL）：https://你的域名:端口/${web_download_path}/config.json ${Font}"
	echo -e "${OK} ${GreenBG} 新的 Windows 客户端（已打包 config 即下即用）：https://你的域名:端口/${web_download_path}/v2rayN-win.zip ${Font}"
fi
}

# 在 website 首页添加 UUID 信息
share_uuid(){
	random_number
	rm -f ${website_dir}/index.html
	cp -rp ${website_dir}/index.bak ${website_dir}/index.html
	sed -i "/\"id\"/c \\\t\t\t\t\t\"id\":\"${UUID}\"" ${v2ray_conf_file}
	sed -i "s/<\/body>/<\/body><div style=\"color:#666666;\"><br\/><br\/><p align=\"center\">UUID:${UUID}<\/p><br\/><\/div>/g" "${website_dir}/index.html"
	systemctl restart v2ray
	echo -e "${OK} ${GreenBG} 执行 UUID 更换任务成功，请访问 Website 首页查看新的 UUID ${Font}"
}

#开启账号共享功能 增加每周一定时更换UUID任务
add_share(){
if [[ -e ${website_dir}/index.bak ]]; then
	echo -e "${Info} ${GreenBG} 账号分享功能已开启，请勿重复操作 ${Font}"
else
	cp -rp ${website_dir}/index.html ${website_dir}/index.bak
	crontab -l >> crontab.txt
	echo "10 12 * * 1 bash /root/h.sh -m" >> crontab.txt
	crontab crontab.txt
	if [[ "${ID}" == "centos" ]];then
		systemctl restart crond
	else
		systemctl restart cron
	fi
	rm -f crontab.txt
	echo -e "${OK} ${GreenBG} 账号分享功能已开启 UUID 将在每周一12点10分更换（服务器时区）并推送至 Website 首页 ${Font}"
	echo -e "${OK} ${GreenBG} 提示：为避免被恶意抓取 该模式下不生成客户端 config.json 文件 ${Font}"
	echo -e "${OK} ${GreenBG} 正在执行首次 UUID 更换任务 ${Font}"
	share_uuid
fi
}

#生成Windows客户端
win64_v2ray(){
	V2RAYN_URL="https://github.com/2dust/v2rayN/releases"
	LATEST_VER=${curl -s ${V2RAYN_URL} --connect-timeout 10 | grep  --color 'releases/tag' | awk -F'<|>' '{print $3}'}
#	TAG_URL="https://api.github.com/repos/v2ray/v2ray-core/releases/latest"
#	LATEST_VER=`curl -s ${TAG_URL} --connect-timeout 10| grep 'tag_name' | cut -d\" -f4`

  rm -rf ${v2ray_win_client_dir}
	mkdir -p ${v2ray_win_client_dir}
	cd ${v2ray_win_client_dir}

	wget https://github.com/2dust/v2rayN/releases/download/${LATEST_VER}/v2rayN-Core.zip
	wget https://github.com/2dust/v2rayN/releases/download/${LATEST_VER}/v2rayN.zip

#	wget https://github.com/dylanbai8/V2Ray_h2-tls_Website_onekey/raw/master/V2rayPro.zip
#	wget https://github.com/v2ray/v2ray-core/releases/download/${LATEST_VER}/v2ray-windows-64.zip
	echo -e "${OK} ${GreenBG} 正在生成Windows客户端 v2ray-core 最新版本 ${LATEST_VER} ${Font}"
	unzip v2rayN-Core.zip
	rm -rf v2rayN-Core.zip
	cp -rp ${v2ray_conf_client} ./v2rayN-Core/config.json
	zip -q -r ${website_dir}/${web_download_path}/v2rayN-win.zip ./v2rayN-Core
	rm -rf ./v2rayN-Core
}

#Bash执行选项
if [[ $# > 0 ]];then
	key="$1"
	case $key in
		-r|--rm_userjson)
		rm_userjson
		;;
		-n|--new_uuid)
		new_uuid
		;;
		-s|--add_share)
		add_share
		;;
		-m|--share_uuid)
		share_uuid
		;;
	esac
else
	main
fi
