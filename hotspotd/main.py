from daemon import Daemonize
from flask import Flask, request, render_template
from subprocess import Popen, PIPE
import os
import re

class Manager():
    def __init__(self, pidfile, config, keep_fds, logger):
        self.config = config
        self.webapp = Flask(__name__)
        self.logger = logger
        # Init base daemon class
        self.daemon = Daemonize(app="hotspotd", pid=pidfile, action=self.start, keep_fds=keep_fds, logger=self.logger)

    def init_iptables(self):
        self.reset_iptables()
        # Set default chain policies
        os.system("iptables -P INPUT DROP")
        os.system("iptables -P FORWARD DROP")
        os.system("iptables -P OUTPUT ACCEPT")
        # Allow loopback access
        os.system("iptables -A INPUT -i lo -j ACCEPT")
        # Ping from outside to inside
        os.system("iptables -A INPUT -p icmp -j ACCEPT")
        # Accept DNS connection from external
        #os.system("iptables -A INPUT -p udp -i eth0 --sport 53 -j ACCEPT")
        # Accept DNS connection from external
        #os.system("iptables -A INPUT -p udp -i eth0 --sport 123 -j ACCEPT")
        # Accept Safe Port from web
        os.system("iptables -A INPUT -i eth0 -j ACCEPT")

        # Allow outbound DNS from wlan0 to local
        os.system("iptables -A INPUT -p udp -i wlan0 -d 10.0.0.1/32 --dport 53 -j ACCEPT")
        # Allow incoming SSH only from a sepcific network
        #os.system("iptables -A INPUT -i eth0 -p tcp --dport 22 -m state --state NEW,ESTABLISHED -j ACCEPT")
        # Prevent DoS attack
        os.system("iptables -A INPUT -p tcp --dport 80 -m limit --limit 25/minute --limit-burst 100 -j ACCEPT")

        # Allow DHCP request
        os.system("iptables  -A INPUT -i wlan0 -p udp --dport 67:68 -j ACCEPT")

        # Accept traffic to Captive Portal from wireless
        os.system("iptables  -A INPUT -i wlan0 -p tcp -d 10.0.0.1/32 --dport 5000 -j ACCEPT")

        # Enable NAT for wlan
        os.system("iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE")

        os.system("iptables -A FORWARD -i eth0 -j ACCEPT")
        #os.system("iptables -A FORWARD -i wlan0 -j ACCEPT")


        # Create chan for Trusted client
        os.system("iptables -N Trusted")
        os.system("iptables -A FORWARD -j Trusted")
        #os.system("iptables -A Trusted -m mac --mac-source 74:81:14:38:e1:4a -j ACCEPT")


        #os.system("iptables -N TrustedNat -t nat")
        #os.system("iptables -t nat -A PREROUTING -j TrustedNat")

        # Redirect ALL web traffic to captive portal
        os.system("iptables -t nat -A PREROUTING -i wlan0 -p tcp --dport 80 -j DNAT --to-destination 10.0.0.1:5000")


        # Enable logging
        os.system("iptables -N LOGGING")
        os.system("iptables -A INPUT -j LOGGING")
        os.system("iptables -A FORWARD -j LOGGING")
        os.system("iptables -A LOGGING -m limit --limit 2/min -j LOG --log-prefix \"IPTables Dropped: \" --log-level 7")
        os.system("iptables -A LOGGING -j DROP")

    def reset_iptables(self):
        os.system("iptables -F")
        os.system("iptables -X")
        os.system("iptables -t nat -F")
        os.system("iptables -t nat -X")
        os.system("iptables -t mangle -F")
        os.system("iptables -t mangle -X")
        os.system("iptables -P INPUT ACCEPT")
        os.system("iptables -P FORWARD ACCEPT")
        os.system("iptables -P OUTPUT ACCEPT")


    def stat_daemon(self):
        self.daemon.start()

    def stop_daemon(self):
        self.reset_iptables()
        self.daemon.exit()

    def restart_daemon(self):
        self.daemon.exit()
        self.daemon.start()

    def start(self, debug=False):
        self.init_iptables()
        self.logger.info('Starting web gui at http://127.0.0.1:5000/...')

        @self.webapp.route('/', defaults={'path': ''})
        @self.webapp.route('/<path:path>')
        def catch_all(path):
            return render_template('index.html')
            #return 'You want path: %s<br/>ip: %s' % (path, self.getMACAddress(request.environ.get('HTTP_X_REAL_IP', request.remote_addr)))

        @self.webapp.route('/register', methods=['POST'])
        def register():
            if request.form['submit'] == 'Register':
                mac = self.getMACAddress(request.environ.get('HTTP_X_REAL_IP', request.remote_addr))
                os.system("iptables -A Trusted -m mac --mac-source %s -j ACCEPT" % mac )
                return render_template('index.html', register=True)

        self.webapp.run(host='10.0.0.1', port=5000, threaded=True, debug=debug)

    def getMACAddress(self, ip):
        pid = Popen(["arp", "-n", ip], stdout=PIPE)
        s = pid.communicate()[0]
        return re.search(r"(([a-f\d]{1,2}\:){5}[a-f\d]{1,2})", s).groups()[0]