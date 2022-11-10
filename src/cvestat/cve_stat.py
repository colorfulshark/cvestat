import argparse
from .nvd_cve import NVDCVE
from .global_logger import GlobalLogger


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
        search.add_argument('--cwe', type=int, nargs='*')
        search.add_argument('--start', type=str)
        search.add_argument('--end', type=str)
        search.add_argument('--vendor', type=str)
        search.add_argument('--product', type=str)
        args = parser.parse_args()
        self.command = args.command
        if (args.command == 'search'):
            self.args['cwe'] = args.cwe
            self.args['start'] = args.start
            self.args['end'] = args.end
            self.args['vendor'] = args.vendor
            self.args['product'] = args.product

    # execute command
    def run(self):
        print(self.command)
        print(self.args)
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

    # search CVE based on options
    def search(self):
        pass

def main():
    CVEStat().run()

if (__name__ == '__main__'):
    main()