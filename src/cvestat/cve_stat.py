import argparse
from .nvd_cve import NVDCVE
from .global_logger import GlobalLogger
from .local_data import LocalDatabase
from .time_stamp import Timestamp
from tabulate import tabulate


class CVEStat:
    def __init__(self):
        self.command = None
        self.args = dict()
        self.parse_args()
        self.gl = GlobalLogger(True)

    def parse_args(self):
        parser = argparse.ArgumentParser()
        subparser = parser.add_subparsers(dest='command', required=True)
        update = subparser.add_parser('update')
        clean = subparser.add_parser('clean')
        search = subparser.add_parser('search')
        search.add_argument('--cpe', type=str, nargs='*')
        search.add_argument('--cwe', type=int, nargs='*')
        search.add_argument('--severity', type=str, nargs='*')
        search.add_argument('--start', type=str)
        search.add_argument('--end', type=str)
        search.add_argument('--show', action='store_true')
        args = parser.parse_args()
        self.command = args.command
        if (args.command == 'search'):
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
        elif (self.command == 'search'):
            self.search()

    # update local data
    def update(self):
        self.gl.info('start updating local data')
        nvdcve = NVDCVE()
        nvdcve.update()

    # clean up local cache
    def clean(self):
        pass

    # show cve info in console
    def show_cve_info(self, cve_set):
        headers = ['cve_id', 'score_v2', 'severity_v2', 'publish_date']
        table_data = []
        for cve_info in cve_set:
            table_data.append([cve_info.cve_id, cve_info.score_v2,
                               cve_info.severity_v2, cve_info.publish])
        self.show_cve_number(cve_set)
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
        if (a['show']):
            self.show_cve_info(cve_set)
        else:
            self.show_cve_number(cve_set)

def main():
    CVEStat().run()
