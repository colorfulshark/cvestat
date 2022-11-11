import re
import sys
sys.path.append('../src')
from cvestat.cve_stat import main
if __name__ == '__main__':
    sys.argv[0] = re.sub(r'(-script\.pyw|\.exe)?$', '', sys.argv[0])
    sys.exit(main())