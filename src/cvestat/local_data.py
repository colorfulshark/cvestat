import os
from appdirs import *
from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, Session, relationship
from sqlalchemy import Column, Integer, String, DateTime, Float, ForeignKey
from sqlalchemy import select


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

Base = declarative_base()
class CVEInfo(Base):
    __tablename__ = 'cve_info'

    id = Column(Integer, primary_key=True)
    cve_id = Column(String(20))
    nvd_url = Column(String)
    description = Column(String)
    score_v2 = Column(Float(1))
    severity_v2 = Column(String(10))
    score_v3 = Column(Float(1))
    severity_v3 = Column(String(10))
    publish = Column(DateTime)
    update = Column(DateTime)
    cpes = relationship('CPEInfo', back_populates='cve', cascade='all, delete')
    cwes = relationship('CWEInfo', back_populates='cve', cascade='all, delete')

    def __repr__(self) -> str:
        return self.cve_id

class CPEInfo(Base):
    __tablename__ = 'cpe_info'

    id = Column(Integer, primary_key=True)
    part = Column(String)
    vendor = Column(String)
    product = Column(String)
    cve_id = Column(Integer, ForeignKey('cve_info.id', ondelete='CASCADE'))
    cve = relationship('CVEInfo', back_populates='cpes')

class CWEInfo(Base):
    __tablename__ = 'cwe_info'

    id = Column(Integer, primary_key=True)
    cwe = Column(String(20))
    cve_id = Column(Integer, ForeignKey('cve_info.id', ondelete='CASCADE'))
    cve = relationship('CVEInfo', back_populates='cwes')

class LocalDatabase:
    def __init__(self):
        self.create_engine()
        self.create_table()

    def create_engine(self):
        db_file = LocalFile().get_db_path()
        self.engine = create_engine('sqlite+pysqlite:///{}'.format(db_file))

    def create_table(self):
        Base.metadata.create_all(self.engine)

    def get_session(self):
        return Session(self.engine)

    def insert(self, session:Session, inst):
        session.add(inst)

    def get_cve_info(self, session:Session, ident):
        return session.get(CVEInfo, ident)

    def delete(self, session:Session, inst):
        session.delete(inst)

    def commit(sell, session:Session):
        session.commit()