import logging
import traceback
from .local_data import LocalFile

class GlobalLogger:
    def __init__(self, init=False):
        self.logger = logging.getLogger('cvestat')
        self.fmt = logging.Formatter('%(asctime)s %(name)s %(levelname)s: %(message)s')
        if(init):
            self.set_handler()

    def set_handler(self, level=logging.DEBUG):
        # log to file
        fh = logging.FileHandler(LocalFile().get_log_path())
        fh.setLevel(level)
        fh.setFormatter(self.fmt)
        # log to console
        ch = logging.StreamHandler()
        ch.setLevel(logging.INFO)
        ch.setFormatter(self.fmt)

        self.logger.setLevel(level)
        self.logger.addHandler(ch)
        self.logger.addHandler(fh)

    def debug(self, msg):
        self.logger.debug(msg)

    def info(self, msg):
        self.logger.info(msg)

    def warning(self, msg):
        self.logger.warning(msg)

    def error(self, msg):
        self.logger.error(msg)
        traceback.format_tb()

    def critical(self, msg):
        self.logger.critical(msg)
