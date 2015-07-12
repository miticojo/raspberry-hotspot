from daemon import Daemonize
from flask import Flask, request, render_template
from subprocess import Popen, PIPE
import os
import re
from datetime import datetime, timedelta
from apscheduler.schedulers.background import BackgroundScheduler


class Manager():

    scheduler_conf = {
    'apscheduler.jobstores.default': {
        'type': 'memory'
    },
    'apscheduler.executors.default': {
        'class': 'apscheduler.executors.pool:ThreadPoolExecutor',
        'max_workers': '20'
    },
    'apscheduler.executors.processpool': {
        'type': 'processpool',
        'max_workers': '5'
    },
    'apscheduler.job_defaults.coalesce': 'false',
    'apscheduler.job_defaults.max_instances': '3',
    'apscheduler.timezone': 'UTC',
    }

    def __init__(self, pidfile, config, keep_fds, logger):
        self.config = config
        self.webapp = Flask(__name__)
        self.logger = logger
        self.scheduler = BackgroundScheduler(self.scheduler_conf)
        self.scheduler.start()
        # Init base daemon class
        self.daemon = Daemonize(app="hotspotd", pid=pidfile, action=self.start, keep_fds=keep_fds, logger=self.logger)

    def init_iptables(self):
        self.reset_iptables()

        self.logger.info("IPTables initializing...")
        # Set default chain policies
        os.system("iptables -P INPUT DROP")
        os.system("iptables -P FORWARD DROP")
        os.system("iptables -P OUTPUT ACCEPT")

        # Allow loopback access
        os.system("iptables -A INPUT -i lo -j ACCEPT")

        # Ping from outside to inside
        os.system("iptables -A INPUT -p icmp -j ACCEPT")

        # Accept Safe Port from web
        os.system("iptables -A INPUT -i eth0 -j ACCEPT")

        # Allow outbound DNS from wlan0 to local
        os.system("iptables -A INPUT -p udp -i wlan0 -d 10.0.0.1/32 --dport 53 -j ACCEPT")

        # Prevent DoS attack
        os.system("iptables -A INPUT -p tcp --dport 80 -m limit --limit 25/minute --limit-burst 100 -j ACCEPT")

        # Allow DHCP request
        os.system("iptables  -A INPUT -i wlan0 -p udp --dport 67:68 -j ACCEPT")

        # Accept traffic to Captive Portal from wireless
        os.system("iptables  -A INPUT -i wlan0 -p tcp -d 10.0.0.1/32 --dport 5000 -j ACCEPT")

        # Enable NAT for wlan
        os.system("iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE")

        os.system("iptables -A FORWARD -i eth0 -j ACCEPT")
        #os.system("iptables -A FORWARD -i wlan0 -m mark --mark 2 -j ACCEPT")

        # Create chan for Trusted client
        os.system("iptables -N Trusted")
        os.system("iptables -A FORWARD -j Trusted")
        os.system("iptables -t nat -N Trusted")
        os.system("iptables -t nat -A PREROUTING -j Trusted")

        #os.system("iptables -A Trusted -m recent --remove")
        #os.system("iptables -A Trusted -t nat -m recent --remove")


        # Redirect ALL web traffic to captive portal
        os.system("iptables -t nat -A PREROUTING -i wlan0 -m mark ! --mark 2 -p tcp --dport 80 -j DNAT --to-destination 10.0.0.1:5000")

        # Enable logging
        os.system("iptables -N LOGGING")
        os.system("iptables -A INPUT -j LOGGING")
        os.system("iptables -A FORWARD -j LOGGING")
        os.system("iptables -A LOGGING -m limit --limit 2/min -j LOG --log-prefix \"IPTables Dropped: \" --log-level 7")
        os.system("iptables -A LOGGING -j DROP")
        self.logger.info("IPTables initialized")


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
        self.logger.info("IPTables resetted")



    def stat_daemon(self):
        self.daemon.start()

    def stop_daemon(self):
        self.scheduler.shutdown()
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
            return render_template('index.html', refer_url=request.base_url)
            #return 'You want path: %s<br/>ip: %s' % (path, self.getMACAddress(request.environ.get('HTTP_X_REAL_IP', request.remote_addr)))

        @self.webapp.route('/register', methods=['POST'])
        def register():
            if request.form['submit'] == 'Register':
                mac = self.getMACAddress(request.environ.get('HTTP_X_REAL_IP', request.remote_addr))
                self.logger.info("Registred new user with IP %s and MAC %s" % (request.environ.get('HTTP_X_REAL_IP', request.remote_addr), mac))

                # Remove previous rule
                os.system("iptables -D Trusted -m mac --mac-source %s -j ACCEPT" % mac )
                os.system("iptables -t nat -D Trusted -m mac --mac-source %s -j MARK --set-mark 2" % mac )

                # Add new rule
                if os.system("iptables -A Trusted -m mac --mac-source %s -j ACCEPT" % mac ) == 0 and \
                    os.system("iptables -t nat -A Trusted -m mac --mac-source %s -j MARK --set-mark 2" % mac ) == 0:

                    self.scheduler.add_job(func=self.deleteExpiredRules, trigger="date",
                                       next_run_time=datetime.now() + timedelta(minutes=self.config["max_time_connection"]),
                                       args=(mac,))

                    return render_template('index.html', register=True, redirect_url=request.form['redirect_url'])

        self.webapp.run(host='10.0.0.1', port=5000, threaded=True, debug=debug)


    def deleteExpiredRules(self, mac):
        self.logger.info("IPTables deleting rules for %s" % mac)
        # Remove rule in N minutes
        os.system("iptables -D Trusted -m mac --mac-source %s -j ACCEPT" % mac )
        os.system("iptables -t nat -D Trusted -m mac --mac-source %s -j MARK --set-mark 2" % mac )

    def getMACAddress(self, ip):
        pid = Popen(["arp", "-n", ip], stdout=PIPE)
        s = pid.communicate()[0]
        return re.search(r"(([a-f\d]{1,2}\:){5}[a-f\d]{1,2})", s).groups()[0]