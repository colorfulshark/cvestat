import os
from appdirs import *
from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, Session
from sqlalchemy import Column, Integer, String, DateTime, ForeignKey


class LocalFile:
    def __init__(self):
        app_name = 'cvestat'
        self.local_cache_dir = self.create_dir(user_cache_dir(app_name))
        self.local_config_dir = self.create_dir(user_config_dir(app_name))
        self.local_log_dir = self.create_dir(user_log_dir(app_name))
        self.local_data_dir = self.create_dir(user_data_dir(app_name))

    def get_log_path(self):
        log_file = 'cvestat.log'
        return os.path.join(self.local_log_dir, log_file)

    def get_db_path(self):
        db_file = 'cvestat.db'
        return os.path.join(self.local_data_dir, db_file)

    def create_dir(self, dir_name):
        if (os.path.exists(dir_name) is False):
            os.mkdir(dir_name)
        return dir_name

BaseTbale = declarative_base()
class CVEInfo(BaseTbale):
    __tablename__ = 'cve_info'

    id = Column(Integer, primary_key=True)
    cve_id = Column(String(20))
    nvd_url = Column(String)
    description = Column(String)
    publish = Column(DateTime)
    update = Column(DateTime)

    def __repr__(self) -> str:
        return self.cve_id

class LocalDatabase:
    def __init__(self):
        self.create_engine()
        self.create_table()

    def create_engine(self):
        db_file = LocalFile().get_db_path()
        self.engine = create_engine('sqlite+pysqlite:///{}'.format(db_file))

    def create_table(self):
        BaseTbale.metadata.create_all(self.engine)

    def get_session(self):
        return Session(self.engine)

    def insert(self, session:Session, inst):
        session.add(inst)

    def commit(sell, session:Session):
        session.commit()