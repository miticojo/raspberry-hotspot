from daemon import Daemonize
from flask import Flask
from time import sleep

class Manager():
    def __init__(self, pidfile, config, keep_fds, logger):
        self.config = config
        self.webapp = Flask(__name__)
        self.logger = logger
        # Init base daemon class
        self.daemon = Daemonize(app="hotspotd", pid=pidfile, action=self.start, keep_fds=keep_fds, logger=self.logger)

    def stat_daemon(self):
        self.daemon.start()

    def stop_daemon(self):
        self.daemon.exit()

    def restart_daemon(self):
        self.daemon.exit()
        self.daemon.start()

    def start(self):
        self.logger.info('Starting web gui at http://127.0.0.1:5000/...')
        self.webapp.run(host='127.0.0.1', port=5000, threaded=True)
        self.logger.info('Web gui closing...')


