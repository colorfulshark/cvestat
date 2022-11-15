import os
from cpe import CPE
from appdirs import *
from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, Session, relationship
from sqlalchemy import Column, Integer, String, DateTime, Float, ForeignKey
from sqlalchemy import select, union
from .time_stamp import Timestamp


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

    def __repr__(self) -> str:
        return 'cpe:/{}:{}:{}'.format(self.part, self.vendor, self.product)

class CWEInfo(Base):
    __tablename__ = 'cwe_info'

    id = Column(Integer, primary_key=True)
    cwe = Column(Integer)
    cve_id = Column(Integer, ForeignKey('cve_info.id', ondelete='CASCADE'))
    cve = relationship('CVEInfo', back_populates='cwes')

    def __repr__(self) -> str:
        return 'CWE-{}'.format(self.cwe)

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

    def query(self, session, cpe_list=None, cwe_list=None,
              severity_list=None, start_date=None, end_date=None):
        # Bacause CVEInfo table uses cve id as the primary key, it's safe to remove duplicates
        # relying on it
        cve_sets = list()
        # get cve set filtered by cpe
        if (cpe_list is not None):
            cve_set_by_cpe = set()
            cve_sets.append(cve_set_by_cpe)
            # generate select statements
            all_stmts = []
            for cpe_str in cpe_list:
                stmt = select(CPEInfo)
                cpe = CPE(cpe_str)
                part = cpe.get_part()[0]
                vendor = cpe.get_vendor()[0]
                product = cpe.get_product()[0]
                stmt = stmt.where(CPEInfo.product == product)
                stmt = stmt.where(CPEInfo.vendor == vendor)
                stmt = stmt.where(CPEInfo.part == part)
                all_stmts.append(stmt)
            u = union(*all_stmts)
            stmt = select(CPEInfo).from_statement(u)
            result = session.execute(stmt).scalars()
            for cpe_info in result:
                cve_set_by_cpe.add(cpe_info.cve)
        # get cve set filtered by cwe
        if (cwe_list is not None):
            cve_set_by_cwe = set()
            cve_sets.append(cve_set_by_cwe)
            # generate select statements
            all_stmts = list()
            for cwe_id in cwe_list:
                stmt = select(CWEInfo).where(CWEInfo.cwe == cwe_id)
                all_stmts.append(stmt)
            u = union(*all_stmts)
            stmt = select(CWEInfo).from_statement(u)
            result = session.execute(stmt).scalars()
            for cwe_info in result:
                cve_set_by_cwe.add(cwe_info.cve)
        # now we get intersection of those sets
        if (len(cve_sets) > 0):
            cve_set = cve_sets[0]
            for next_set in cve_sets[1:]:
                cve_set = cve_set.intersection(next_set)
        else:
            # no cpe or cwe filter, just select all
            stmt = select(CVEInfo)
            result = session.execute(stmt).scalars()
            cve_set = set(result)
        # next filter the result by severity
        if (severity_list is not None):
            pre_set = cve_set
            cve_set = set()
            for cve_info in pre_set:
                if (cve_info.severity_v2 in severity_list):
                    cve_set.add(cve_info)
        # finally filter the result by time range
        if (start_date is not None or end_date is not None):
            ts = Timestamp()
            pre_set = cve_set
            cve_set = set()
            if (start_date is None):
                start_date = ts.get_min_datetime()
            if (end_date is None):
                end_date = ts.get_max_datetime()
            for cve_info in pre_set:
                if (cve_info.publish >= start_date and
                    cve_info.publish < end_date):
                    cve_set.add(cve_info)
        return cve_set

    def delete(self, session:Session, inst):
        session.delete(inst)

    def commit(sell, session:Session):
        session.commit()