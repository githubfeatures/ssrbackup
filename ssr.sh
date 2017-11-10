#! /bin/bash
PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:~/bin
export PATH
clear
logo="\n\033[1;34m===============================================================\033[0m\n\n\033[1;36m          欢迎使用 shadowsocks-R 一键脚本                                      \033[0m\n\n\033[1;36m          支持系统: CentOS 6+, Debian 7+, Ubuntu 12+                          \033[0m\n\n\033[1;36m          Thanks: @breakwa11 <https://twitter.com/breakwa11>                         \033[0m\n\n\033[1;36m          URL:<http://shiyu.pro>                   \033[0m\n\n\033[1;36m                                                                       整理:Shiyu  \033[m\n\n\033[1;34m===============================================================\033[0m";
echo -e ${logo}
echo
echo
#Current folder
cur_dir=`pwd`
# Get public IP address
IP=$(ip addr | egrep -o '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | egrep -v "^192\.168|^172\.1[6-9]\.|^172\.2[0-9]\.|^172\.3[0-2]\.|^10\.|^127\.|^255\.|^0\." | head -n 1)
if [[ "$IP" = "" ]]; then
	IP=`curl -s http://shiyu.pro/1ip.php`
fi

# Make sure only root can run our script
function rootness(){
	if [[ $EUID -ne 0 ]]; then
	   echo "Error:This script must be run as root!" 1>&2
	   exit 1
	fi
}

# Check OS
function checkos(){
	if [ -f /etc/redhat-release ];then
		OS='CentOS'
	elif [ ! -z "`cat /etc/issue | grep bian`" ];then
		OS='Debian'
	elif [ ! -z "`cat /etc/issue | grep Ubuntu`" ];then
		OS='Ubuntu'
	else
		echo "Not support OS, Please reinstall OS and retry!"
		exit 1
	fi
}

# Get version
function getversion(){
	if [[ -s /etc/redhat-release ]];then
		grep -oE  "[0-9.]+" /etc/redhat-release
	else    
		grep -oE  "[0-9.]+" /etc/issue
	fi    
}

# CentOS version
function centosversion(){
	local code=$1
	local version="`getversion`"
	local main_ver=${version%%.*}
	if [ $main_ver == $code ];then
		return 0
	else
		return 1
	fi        
}

# Disable selinux
function disable_selinux(){
if [ -s /etc/selinux/config ] && grep 'SELINUX=enforcing' /etc/selinux/config; then
	sed -i 's/SELINUX=enforcing/SELINUX=disabled/g' /etc/selinux/config
	setenforce 0
fi
}

# Pre-installation settings
function pre_install(){
	# Not support CentOS 5
	if centosversion 5; then
		echo "Not support CentOS 5, please change OS to CentOS 6+/Debian 7+/Ubuntu 12+ and retry."
		exit 1
	fi
# Set ShadowsocksR config password
echo 
echo
echo -e "IP: \033[1;4;36m${IP}\033[0m"
echo
read -p "请设置SSR连接密码(默认: shiyu): " shadowsockspwd
[ -z "$shadowsockspwd" ] && shadowsockspwd="shiyu"
echo
echo "---------------------------"
echo -e "密码: \033[4;36m${shadowsockspwd}\033[0m"
echo "---------------------------"
echo
# Set ShadowsocksR config port
echo -e  "接下来会依次开通\033[1;4;36m9493、80、8080、53、443、1388\033[0m端口，如果无需修改，回车默认即可。"
echo
echo -e  "注：\033[1;41;37m如果自定义设置端口，为避免冲突，请确定各个端口各不相同！\033[0m"
echo
read -p "按回车键开始配置端口…" anykey
while true
do
echo -e "端口范围: [1～65535]  仅限阿拉伯数字"
echo
read -p "请设置远程连接端口① (回车默认: 9493): " shadowsocksport1
echo
echo -n "端口检查中     "
sleep 0.5
[ -z "$shadowsocksport1" ] && shadowsocksport1="9493"
  expr $shadowsocksport1 + 0 &>/dev/null
	if [ $? -eq 0 ]; then
		if [ $shadowsocksport1 -ge 1 ] && [ $shadowsocksport1 -le 65535 ]; then
			echo "[OK]"
			echo
			echo "---------------------------"
			echo -e "端口①: \033[4;36m${shadowsocksport1}\033[0m"
			echo "---------------------------"
			echo
			break
		else
			echo "[NO] 请输入1--65535之间的数字。"
			echo
		fi
	else
		echo "[NO] 请输入阿拉伯数字。"
		echo
	fi
done
while true
do
echo -e "端口范围: [1～65535]  仅限阿拉伯数字"
echo
read -p "请设置远程连接端口② (回车默认: 80): " shadowsocksport2
echo
echo -n "端口检查中     "
sleep 0.5
[ -z "$shadowsocksport2" ] && shadowsocksport2="80"
  expr $shadowsocksport2 + 0 &>/dev/null
	if [ $? -eq 0 ]; then
		if [ $shadowsocksport2 -ge 1 ] && [ $shadowsocksport2 -le 65535 ]; then
			if [ "$shadowsocksport1" != "$shadowsocksport2" ]; then
			echo "[OK]"
			echo
			echo "---------------------------"
			echo -e "端口②: \033[4;36m${shadowsocksport2}\033[0m"
			echo "---------------------------"
			echo
			break
			else
			echo "[NO] 端口冲突。"
			echo
			fi
		else
			echo "[NO] 请输入1--65535之间的数字。"
			echo
		fi
	else
		echo "[NO] 请输入阿拉伯数字。"
		echo
	fi
done     
while true
do
echo -e "端口范围: [1～65535]  仅限阿拉伯数字"
echo
read -p "请设置远程连接端口③ (回车默认: 8080): " shadowsocksport3
echo
echo -n "端口检查中     "
sleep 0.5
[ -z "$shadowsocksport3" ] && shadowsocksport3="8080"
  expr $shadowsocksport3 + 0 &>/dev/null
	if [ $? -eq 0 ]; then
		if [ $shadowsocksport3 -ge 1 ] && [ $shadowsocksport3 -le 65535 ]; then
			if [ "$shadowsocksport1" == "$shadowsocksport3" ] || [ "$shadowsocksport2" == "$shadowsocksport3" ]; then
			 echo "[NO] 端口冲突。"
			 echo
			 else
			echo "[OK]"
			echo
			echo "---------------------------"
			echo -e "端口③: \033[4;36m${shadowsocksport3}\033[0m"
			echo "---------------------------"
			echo
			break
			fi
		else
			echo "[NO] 请输入1--65535之间的数字。"
			echo
		fi
	else
		echo "[NO] 请输入阿拉伯数字。"
		echo
	fi
done
while true
do
echo -e "端口范围: [1～65535]  仅限阿拉伯数字"
echo
read -p "请设置远程连接端口④ (回车默认: 53): " shadowsocksport4
echo
echo -n "端口检查中     "
sleep 0.5
[ -z "$shadowsocksport4" ] && shadowsocksport4="53"
  expr $shadowsocksport4 + 0 &>/dev/null
	if [ $? -eq 0 ]; then
		if [ $shadowsocksport4 -ge 1 ] && [ $shadowsocksport4 -le 65535 ]; then
			 if [ "$shadowsocksport3" == "$shadowsocksport4" ] || [ "$shadowsocksport4" == "$shadowsocksport2" ] || [ "$shadowsocksport1" == "$shadowsocksport4" ]; then
			echo "[NO] 端口冲突。"
			echo
			else
			echo "[OK]"
			echo
			echo "---------------------------"
			echo -e "端口④: \033[4;36m${shadowsocksport4}\033[0m"
			echo "---------------------------"
			echo
			break
			fi
		else
			echo "[NO] 请输入1--65535之间的数字。"
			echo
		fi
	else
		echo "[NO] 请输入阿拉伯数字。"
		echo
	fi
done
while true
do
echo -e "端口范围: [1～65535]  仅限阿拉伯数字"
echo
read -p "请设置远程连接端口⑤ (回车默认: 443): " shadowsocksport5
echo
echo -n "端口检查中     "
sleep 0.5
[ -z "$shadowsocksport5" ] && shadowsocksport5="443"
  expr $shadowsocksport5 + 0 &>/dev/null
	if [ $? -eq 0 ]; then
		if [ $shadowsocksport5 -ge 1 ] && [ $shadowsocksport5 -le 65535 ]; then
			if [ "$shadowsocksport1" == "$shadowsocksport5" ] || [ "$shadowsocksport2" == "$shadowsocksport5" ] || [ "$shadowsocksport3" == "$shadowsocksport5" ] || [ "$shadowsocksport4" == "$shadowsocksport5" ]; then
			echo "[NO] 端口冲突。"
			echo
			else
			echo "[OK]"
			echo
			echo "---------------------------"
			echo -e "端口⑤: \033[4;36m${shadowsocksport5}\033[0m"
			echo "---------------------------"
			echo
			break
			fi
		else
			 echo "[NO] 请输入1--65535之间的数字。"
			 echo
		fi
	else
		echo "[NO] 请输入阿拉伯数字。"
		echo
	 fi
done
while true
do
echo -e "端口范围: [1～65535]  仅限阿拉伯数字"
echo
read -p "请设置远程连接端口⑥ (回车默认: 1388): " shadowsocksport6
echo
echo -n "端口检查中     "
sleep 0.5
[ -z "$shadowsocksport6" ] && shadowsocksport6="1388"
  expr $shadowsocksport6 + 0 &>/dev/null
	if [ $? -eq 0 ]; then
		if [ $shadowsocksport6 -ge 1 ] && [ $shadowsocksport6 -le 65535 ]; then
			if [ "$shadowsocksport1" == "$shadowsocksport6" ] || [ "$shadowsocksport2" == "$shadowsocksport6" ] || [ "$shadowsocksport3" == "$shadowsocksport6" ] || [ "$shadowsocksport4" == "$shadowsocksport6" ] || [ "$shadowsocksport5" == "$shadowsocksport6" ]; then
			echo "[NO] 端口冲突。"
			echo
			else
			echo "[OK]"
			echo
			echo "---------------------------"
			echo -e "端口⑥: \033[4;36m${shadowsocksport6}\033[0m"
			echo "---------------------------"
			echo
			break
			fi
		else
		  echo "[NO] 请输入1--65535之间的数字。"
		  echo
		fi
	else
		echo "[NO] 请输入阿拉伯数字。"
		echo
 
	fi
done

get_char(){
		SAVEDSTTY=`stty -g`
		stty -echo
		stty cbreak
		dd if=/dev/tty bs=1 count=1 2> /dev/null
		stty -raw
		stty echo
		stty $SAVEDSTTY
}
echo
echo "配置完成，请按下回车键开始搭建..."
char=`get_char`
# Install necessary dependencies
if [ "$OS" == 'CentOS' ]; then
		yum install -y wget unzip openssl-devel gcc swig python python-devel python-setuptools autoconf libtool libevent git ntpdate
		yum install -y m2crypto automake make curl curl-devel zlib-devel perl perl-devel cpio expat-devel gettext-devel
	else
		apt-get -y update
		apt-get -y install python python-dev python-pip python-m2crypto curl wget unzip gcc swig automake make perl cpio build-essential git ntpdate
	fi
	cd $cur_dir
}

# Download files
function download_files(){
	# Download libsodium file
	if ! wget --no-check-certificate -O libsodium-1.0.12.tar.gz https://raw.githubusercontent.com/githubfeatures/ssrbackup/master/SSR/libsodium/libsodium-1.0.12.tar.gz; then
		echo "Failed to download libsodium file!"
		exit 1
	fi
	# Download ShadowsocksR file
	if ! wget --no-check-certificate -O shadowsocks-manyuser.zip https://raw.githubusercontent.com/githubfeatures/ssrbackup/master/SSR/ShadowsocksR/shadowsocks-manyuser.zip; then
		echo "Failed to download ShadowsocksR file!"
		exit 1
	fi
	# Download ShadowsocksR chkconfig file
	if [ "$OS" == 'CentOS' ]; then
		if ! wget --no-check-certificate https://raw.githubusercontent.com/githubfeatures/ssrbackup/master/SSR/chkconfig/shadowsocksR -O /etc/init.d/shadowsocks; then
			echo "Failed to download ShadowsocksR chkconfig file!"
			exit 1
		fi
	else
		if ! wget --no-check-certificate https://raw.githubusercontent.com/githubfeatures/ssrbackup/master/SSR/chkconfig/shadowsocksR-debian -O /etc/init.d/shadowsocks; then
			echo "Failed to download ShadowsocksR chkconfig file!"
			exit 1
		fi
	fi
}

# firewall set
function firewall_set(){
  echo "firewall set start..."
	if centosversion 6; then
		/etc/init.d/iptables status > /dev/null 2>&1
		if [ $? -eq 0 ]; then
				iptables -I INPUT -m state --state NEW -m tcp -p tcp --dport ${shadowsocksport1} -j ACCEPT
				iptables -I INPUT -m state --state NEW -m tcp -p tcp --dport ${shadowsocksport2} -j ACCEPT
				iptables -I INPUT -m state --state NEW -m tcp -p tcp --dport ${shadowsocksport3} -j ACCEPT
				iptables -I INPUT -m state --state NEW -m tcp -p tcp --dport ${shadowsocksport4} -j ACCEPT
				iptables -I INPUT -m state --state NEW -m tcp -p tcp --dport ${shadowsocksport5} -j ACCEPT
				iptables -I INPUT -m state --state NEW -m tcp -p tcp --dport ${shadowsocksport6} -j ACCEPT
				iptables -I INPUT -m state --state NEW -m udp -p udp --dport ${shadowsocksport1} -j ACCEPT
				iptables -I INPUT -m state --state NEW -m udp -p udp --dport ${shadowsocksport2} -j ACCEPT
				iptables -I INPUT -m state --state NEW -m udp -p udp --dport ${shadowsocksport3} -j ACCEPT
				iptables -I INPUT -m state --state NEW -m udp -p udp --dport ${shadowsocksport4} -j ACCEPT
				iptables -I INPUT -m state --state NEW -m udp -p udp --dport ${shadowsocksport5} -j ACCEPT
				iptables -I INPUT -m state --state NEW -m udp -p udp --dport ${shadowsocksport6} -j ACCEPT
				/etc/init.d/iptables save
				/etc/init.d/iptables restart
		else
			echo "WARNING: iptables looks like shutdown or not installed, please manually set it if necessary."
		fi
  elif centosversion 7; then
  systemctl status firewalld > /dev/null 2>&1
	  if [ $? -eq 0 ];then
			firewall-cmd --permanent --zone=public --add-port=${shadowsocksport1}/tcp
			firewall-cmd --permanent --zone=public --add-port=${shadowsocksport2}/tcp
			firewall-cmd --permanent --zone=public --add-port=${shadowsocksport3}/tcp
			firewall-cmd --permanent --zone=public --add-port=${shadowsocksport4}/tcp
			firewall-cmd --permanent --zone=public --add-port=${shadowsocksport5}/tcp
			firewall-cmd --permanent --zone=public --add-port=${shadowsocksport6}/tcp
			firewall-cmd --permanent --zone=public --add-port=${shadowsocksport1}/udp
			firewall-cmd --permanent --zone=public --add-port=${shadowsocksport2}/udp
			firewall-cmd --permanent --zone=public --add-port=${shadowsocksport3}/udp
			firewall-cmd --permanent --zone=public --add-port=${shadowsocksport4}/udp
			firewall-cmd --permanent --zone=public --add-port=${shadowsocksport5}/udp
			firewall-cmd --permanent --zone=public --add-port=${shadowsocksport6}/udp
			firewall-cmd --reload
	  else
					/etc/init.d/iptables status > /dev/null 2>&1
			if [ $? -eq 0 ]; then
					iptables -I INPUT -m state --state NEW -m tcp -p tcp --dport ${shadowsocksport1} -j ACCEPT
					iptables -I INPUT -m state --state NEW -m tcp -p tcp --dport ${shadowsocksport2} -j ACCEPT
					iptables -I INPUT -m state --state NEW -m tcp -p tcp --dport ${shadowsocksport3} -j ACCEPT
					iptables -I INPUT -m state --state NEW -m tcp -p tcp --dport ${shadowsocksport4} -j ACCEPT
					iptables -I INPUT -m state --state NEW -m tcp -p tcp --dport ${shadowsocksport5} -j ACCEPT
					iptables -I INPUT -m state --state NEW -m tcp -p tcp --dport ${shadowsocksport6} -j ACCEPT
					iptables -I INPUT -m state --state NEW -m udp -p udp --dport ${shadowsocksport1} -j ACCEPT
					iptables -I INPUT -m state --state NEW -m udp -p udp --dport ${shadowsocksport2} -j ACCEPT
					iptables -I INPUT -m state --state NEW -m udp -p udp --dport ${shadowsocksport3} -j ACCEPT
					iptables -I INPUT -m state --state NEW -m udp -p udp --dport ${shadowsocksport4} -j ACCEPT
					iptables -I INPUT -m state --state NEW -m udp -p udp --dport ${shadowsocksport5} -j ACCEPT
					iptables -I INPUT -m state --state NEW -m udp -p udp --dport ${shadowsocksport6} -j ACCEPT
					/etc/init.d/iptables save
					/etc/init.d/iptables restart
			else
				echo "WARNING: firewall like shutdown or not installed, please manually set it if necessary."
			fi		
		fi
	fi
	echo "firewall set completed..."
}

# Config ShadowsocksR
function config_shadowsocks(){
	cat > /etc/shadowsocks.json<<-EOF
{
	"server":"0.0.0.0",
	"server_ipv6": "[::]",
	"local_address":"127.0.0.1",
	"local_port":1080,
	"port_password": 
	{
		"${shadowsocksport6}":{"protocol":"auth_aes128_md5", "password":"${shadowsockspwd}", "obfs":"tls1.2_ticket_auth", "obfs_param":""},
		"${shadowsocksport1}":"${shadowsockspwd}",
		"${shadowsocksport2}":"${shadowsockspwd}",
		"${shadowsocksport3}":"${shadowsockspwd}",
		"${shadowsocksport4}":"${shadowsockspwd}",
		"${shadowsocksport5}":"${shadowsockspwd}"
	},
	"timeout":200,
	"method":"chacha20",
	"protocol": "auth_sha1_v4",
	"protocol_param": "",
	"obfs": "http_simple",
	"obfs_param": "",
	"redirect": "",
	"dns_ipv6": false,
	"fast_open": false,
	"workers": 0

}
EOF
}

# Install ShadowsocksR
function install_ss(){
	# Install libsodium
	tar zxf libsodium-1.0.12.tar.gz
	cd $cur_dir/libsodium-1.0.12
	./configure && make && make install
	echo "/usr/local/lib" > /etc/ld.so.conf.d/local.conf
	ldconfig
	# Install ShadowsocksR
	cd $cur_dir
	 unzip -q shadowsocks-manyuser.zip
	 mv shadowsocks-manyuser /usr/local/shadowsocks/
	if [ -f /usr/local/shadowsocks/server.py ]; then
		cp /etc/init.d/shadowsocks /bin/SSR
		chmod +x /etc/init.d/shadowsocks
		chmod +x /bin/SSR
		# Add run on system start up
		if [ "$OS" == 'CentOS' ]; then
			chkconfig --add shadowsocks
			chkconfig shadowsocks on
		else
			update-rc.d -f shadowsocks defaults
		fi
		 # Run ShadowsocksR in the background
		sleep 3
		clear
		echo -e ${logo}
		echo
		SSR start
		echo
		echo -e "shadowsocksR安装完成！"
		echo
		echo -e "请牢记以下配置，建议截图或者复制文本。"
		echo
		echo -e "服务器IP:  \033[1;41;37m ${IP} \033[0m            "
		echo -e "远程端口:  \033[1;41;37m ${shadowsocksport1} ${shadowsocksport2} ${shadowsocksport3} ${shadowsocksport4} ${shadowsocksport5}\033[0m"
		echo -e "连接密码:  \033[1;41;37m ${shadowsockspwd} \033[0m"
		echo -e "本地端口:  \033[1;41;37m 1080 \033[0m             "
		echo -e "加密方法:  \033[1;41;37m chacha20 \033[0m     "
		echo -e "协议:      \033[1;41;37m auth_sha1_v4 \033[0m    "
		echo -e "混淆方式:  \033[1;41;37m http_simple \033[0m  "
		echo
		echo
		echo -e "\033[1;41;37m ${shadowsocksport6} \033[0m  端口协议为: auth_aes128_md5 。混淆方式为: tls1.2_ticket_auth"
		echo
		echo -e "如果电脑端使用网速很慢，电脑端请尝试使用端口 ${shadowsocksport6}"
		echo -e "或者更改配置文件的协议和混淆方式解决。"
		echo -e "修改配置文件具体参考http://shiyu.pro/archives/ssr-obfs.html"
		echo
echo -e "
===============================================
   启动        停止       状态          重启      
-----------------------------------------------
SSR start | SSR stop | SSR status | SSR restart
==============================================="        
	echo
	else
		echo "Shadowsocks install failed!"
		install_cleanup
		exit 1
	fi
}

function check_datetime(){
 echo -e "正在校准中国时间..."
	rm -rf /etc/localtime
	ln -s /usr/share/zoneinfo/Asia/Shanghai /etc/localtime
	ntpdate 1.cn.pool.ntp.org
}

# Install cleanup
function install_cleanup(){
	cd $cur_dir
	rm -rf SSR
	rm -rf shadowsocks*
	rm -rf shadowsocks-manyuser
	rm -rf libsodium-1.0.12.tar.gz
	rm -rf libsodium-1.0.12
}


# Uninstall ShadowsocksR
function uninstall_shadowsocks(){
	printf "uninstall shadowsocksr? (y/n) "
	printf "\n"
	read -p "(Default: n):" answer
	if [ -z $answer ]; then
		answer="n"
	fi
	if [ "$answer" = "y" ]; then
		/etc/init.d/shadowsocks status > /dev/null 2>&1
		if [ $? -eq 0 ]; then
			/etc/init.d/shadowsocks stop
		fi
		checkos
		if [ "$OS" == 'CentOS' ]; then
			chkconfig --del shadowsocks
		else
			update-rc.d -f shadowsocks remove
		fi
		rm -f /etc/shadowsocks.json
		rm -f /etc/init.d/shadowsocks
		rm -rf /usr/local/shadowsocks
		echo "uninstall shadowsocksr success!"
	else
		echo "uninstall failed."
	fi
}


# Install ShadowsocksR
function install_shadowsocks(){
	checkos
	rootness
	disable_selinux
	pre_install
	download_files
	config_shadowsocks
	install_ss
	if [ "$OS" == 'CentOS' ]; then
		firewall_set > /dev/null 2>&1
	fi
	check_datetime
	install_cleanup
	
}

# Initialization step
action=$1
[ -z $1 ] && action=install
case "$action" in
install)
	install_shadowsocks
	;;
uninstall)
	uninstall_shadowsocks
	;;
*)
	echo "Arguments error! [${action} ]"
	echo "Usage: `basename $0` {install|uninstall}"
	;;
esac
