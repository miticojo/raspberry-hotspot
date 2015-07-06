# base libraries imported
import sys
import yaml
import logging
import os
import signal

# application import
from hotspotd.main import Manager


def init_logger(level, log_path, syslog_server=None):
    global logger, fh, ch, formatter
    logger = logging.getLogger(__name__)
    logger.setLevel(logging.getLevelName(level.upper()))
    # Create log folder if doesn't exist
    if not os.path.exists(os.path.dirname(log_path)):
        os.makedirs(os.path.dirname(log_path))

    fh = logging.FileHandler("%s" % log_path)
    fh.setLevel(logging.getLevelName(level.upper()))
    ch = logging.StreamHandler()
    ch.setLevel(logging.getLevelName(level.upper()))
    formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    fh.setFormatter(formatter)
    ch.setFormatter(formatter)
    # add the handlers to the logger
    logger.addHandler(fh)
    logger.addHandler(ch)


if __name__ == "__main__":
    conf = yaml.load(open('conf/config.yml'))
    init_logger( level=conf["logging"]["level"],
                 log_path=conf["logging"]["path"],
                 syslog_server=conf["logging"]["remote_syslog"])

    keep_fds = [fh.stream.fileno()]

    daemon = Manager(
        pidfile='hotspotd.pid',
        config=conf,
        keep_fds=keep_fds,
        logger=logger
    )

    if len(sys.argv) == 2:
            if 'start' == sys.argv[1]:
                    logger.info("starting Hotspotd manager...")
                    daemon.stat_daemon()
            elif 'stop' == sys.argv[1]:
                    logger.info("stopping Hotspotd manager...")
                    daemon.stop_daemon()
                    print "%s stopped" % sys.argv[0]
                    sys.exit(0)
            elif 'restart' == sys.argv[1]:
                    daemon.restart_daemon()
            elif 'fg' == sys.argv[1]:
                    logger.info("starting Hotspotd in foreground....")
                    daemon.start()
            else:
                    print "Unknown command"
                    sys.exit(2)
            sys.exit(0)
    else:
            print "usage: %s start|stop|restart" % sys.argv[0]
            sys.exit(2)