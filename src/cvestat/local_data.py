from appdirs import *
import os

class LocalFile:
    def __init__(self):
        app_name = 'cvestat'
        self.local_cache_dir = self.create_dir(user_cache_dir(app_name))
        self.local_config_dir = self.create_dir(user_config_dir(app_name))
        self.local_log_dir = self.create_dir(user_log_dir(app_name))

    def get_log_path(self):
        log_file = 'cvestat.log'
        return os.path.join(self.local_log_dir, log_file)

    def create_dir(self, dir_name):
        if (os.path.exists(dir_name) is False):
            os.mkdir(dir_name)
        return dir_name

class LocalDatabase:
    def __init__(self):
        pass