os.system("iptables -F")
# Set default chain policies
os.system("iptables -P INPUT DROP")
os.system("iptables -P FORWARD DROP")
os.system("iptables -P OUTPUT DROP")
# Allow loopback access
os.system("iptables -A INPUT -i lo -j ACCEPT")
os.system("iptables -A OUTPUT -o lo -j ACCEPT")
# Ping from outside to inside
os.system("iptables -A INPUT -p icmp --icmp-type echo-request -j ACCEPT")
os.system("iptables -A OUTPUT -p icmp --icmp-type echo-reply -j ACCEPT")
# Allow outbound DNS from eth0
os.system("iptables -A OUTPUT -p udp -o eth0 --dport 53 -j ACCEPT")
os.system("iptables -A INPUT -p udp -i eth0 --sport 53 -j ACCEPT")
# Allow outbound DNS from wlan0 to local
os.system("iptables -A OUTPUT -p udp -o wlan0 -d 10.0.0.0/24 ---dport 53 -j ACCEPT")
os.system("iptables -A INPUT -p udp -i wlan0 -d 10.0.0.1/32 --sport 53 -j ACCEPT")
# 5. Allow incoming SSH only from a sepcific network
os.system("iptables -A INPUT -i eth0 -p tcp -i eth0 --dport 22 -m state --state NEW,ESTABLISHED -j ACCEPT")
os.system("iptables -A OUTPUT -o eth0 -p tcp --sport 22 -m state --state ESTABLISHED -j ACCEPT")