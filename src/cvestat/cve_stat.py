import argparse
from .nvd_cve import NVDCVE
from .global_logger import GlobalLogger
from .local_data import LocalDatabase, Record, LocalFile
from .time_stamp import Timestamp
from tabulate import tabulate
from cwe2.database import Database


class CVEStat:
    def __init__(self):
        self.command = None
        self.args = dict()
        self.parse_args()
        self.gl = GlobalLogger(True)

    def parse_args(self):
        parser = argparse.ArgumentParser()
        subparser = parser.add_subparsers(dest='command')
        update = subparser.add_parser('update', help='Fetch new CVEs from upstream')
        clean = subparser.add_parser('clean', help='Delete temp files and database')
        parser.add_argument('--cpe', type=str, nargs='*')
        parser.add_argument('--cwe', type=int, nargs='*')
        parser.add_argument('--severity', type=str, nargs='*')
        parser.add_argument('--start', type=str)
        parser.add_argument('--end', type=str)
        parser.add_argument('--show', type=str, choices=('cve', 'cwe'))
        args = parser.parse_args()
        self.command = args.command
        if (self.command is None):
            ts = Timestamp()
            self.args['cpe'] = args.cpe
            self.args['cwe'] = args.cwe
            self.args['severity'] = args.severity
            self.args['start'] = args.start
            self.args['end'] = args.end
            self.args['show'] = args.show
            if (args.start is not None):
                self.args['start'] = ts.get_datetime(args.start, '%Y-%m-%d')
            if (args.end is not None):
                self.args['end'] = ts.get_datetime(args.end, '%Y-%m-%d')

    # execute command
    def run(self):
        self.gl.debug('command: {}'.format(self.command))
        self.gl.debug('arguments: {}'.format(self.args))
        if (self.command == 'update'):
            self.update()
        elif (self.command == 'clean'):
            self.clean()
        else:
            self.search()

    # update local data
    def update(self):
        ldb = LocalDatabase()
        ts = Timestamp()
        session = ldb.get_session()
        self.gl.info('start updating local data')
        old_ts = ts.get_min_datetime()
        new_ts = ts.get_cur_datetime()
        record = ldb.load_record(session)
        if (record is not None):
            old_ts = record.timestamp
        count = NVDCVE().update(old_ts, new_ts)
        if (count != 0):
            record = Record(id=None, source='nvd', count=count, timestamp=new_ts)
            ldb.save_record(session, record)
        self.gl.info('finish updating local data')

    # clean up local cache
    def clean(self):
        lf = LocalFile()
        lf.cleanall()

    # show cve info in console
    def show_cve_info(self, cve_set):
        headers = ['cve_id', 'score_v2', 'severity_v2', 'publish_date']
        table_data = []
        for cve_info in cve_set:
            table_data.append([cve_info.cve_id, cve_info.score_v2,
                               cve_info.severity_v2, cve_info.publish])
        self.show_cve_number(cve_set)
        print(tabulate(table_data, headers))

    def show_cwe_info(self, cve_set):
        cwe_db = Database()
        cwe_stat = dict()
        for cve_info in cve_set:
            cwe_list = cve_info.cwes
            for cwe_info in cwe_list:
                if (cwe_stat.get(cwe_info.cwe) is None):
                    cwe_stat[cwe_info.cwe] = 0
                cwe_stat[cwe_info.cwe] += 1
        cwe_stat = dict(sorted(cwe_stat.items(), key=lambda item: item[1]))
        headers = ['CWE', 'Numbers', 'Description']
        table_data = []
        for cwe, number in cwe_stat.items():
            try:
                weakness = cwe_db.get(cwe)
                cwe_desc = weakness.name
            except:
                cwe_desc = ''
            table_data.append([cwe, number, cwe_desc])
        print(tabulate(table_data, headers))

    # show cve number in console
    def show_cve_number(self, cve_set):
        print('CVE Numbers: {}'.format(len(cve_set)))

    # search CVE based on options
    def search(self):
        ldb = LocalDatabase()
        session = ldb.get_session()
        a = self.args
        cve_set = ldb.query(session, a['cpe'], a['cwe'], a['severity'], a['start'], a['end'])
        if (a['show'] == 'cve'):
            self.show_cve_info(cve_set)
        elif (a['show'] == 'cwe'):
            self.show_cwe_info(cve_set)
        else:
            self.show_cve_number(cve_set)

def main():
    CVEStat().run()
