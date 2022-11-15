import time
import json
import requests
from cpe import CPE
from .local_data import LocalDatabase, CVEInfo, CPEInfo, CWEInfo
from .time_stamp import Timestamp
from .global_logger import GlobalLogger

class NVDCVE:
    def __init__(self):
        self.gl = GlobalLogger()
        self.ts = Timestamp()
        self.ldb = LocalDatabase()
        self.url = 'https://services.nvd.nist.gov/rest/json/cves/1.0'
        self.request_size = 2000
        self.tsform = '%Y-%m-%dT%H:%M:%S:000 UTC'
        # disable SSL warnings
        requests.packages.urllib3.disable_warnings()

    # update CVE in database
    def update(self, old_ts, new_ts):
        self.gl.info("Start updating CVE bundle")
        session = self.ldb.get_session()
        new_cve_list = self.request_new_cve(old_ts, new_ts)
        for c in new_cve_list:
            cve_item = CVEItem(c)
            self.update_cve(session, cve_item)
        self.ldb.commit(session)
        self.gl.info("Finish updating CVE bundle")
        return len(new_cve_list)

    def update_cve(self, session, cve_item):
        old_cve_info = self.ldb.get_cve_info(session, cve_item.primary_key)
        new_cve_info = cve_item.get_cve_info()
        if (old_cve_info is not None):
            self.ldb.delete(session, old_cve_info)
        self.ldb.insert(session, new_cve_info)

    def get_param(self, start_index=None, result_per_page=None,
                  mod_start_date=None, mod_end_date=None,
                  keyword=None, cpe_match_string=None, add_ons=None):
        param = {}
        key = ['startIndex', 'resultsPerPage', 'modStartDate',
               'modEndDate', 'keyword', 'cpeMatchString', 'addOns']
        if (mod_start_date is not None):
            mod_start_date = self.ts.get_datetime_str(mod_start_date, self.tsform)
        if (mod_end_date is not None):
            mod_end_date = self.ts.get_datetime_str(mod_end_date, self.tsform)
        data = [start_index, result_per_page, mod_start_date,
                mod_end_date, keyword, cpe_match_string, add_ons]

        for i in range(len(key)):
            if (data[i] is not None):
                param[key[i]] = data[i]
        return param

    def request_new_cve(self, start_date, end_date):
        cve_list = []
        while(True):
            # this is required by NVD
            if(start_date >= end_date):
                break
            cur_end = self.ts.jump_days(start_date, 120)
            if (cur_end > end_date):
                cur_end = end_date
            new_cves = self.request_cve_from_nvd(start_date, cur_end)
            cve_list.extend(new_cves)
            print('{}, {}'.format(start_date, cur_end))
            start_date = cur_end
        return cve_list

    # NOTICE: the range between start_date and end_date must not over 120 days
    # https://nvd.nist.gov/developers/vulnerabilities
    def request_cve_from_nvd(self, start_date, end_date):
        cve_list = []
        total = 0
        while(True):
            param = self.get_param(start_index=total,
                                   result_per_page=self.request_size,
                                   mod_start_date=start_date,
                                   mod_end_date=end_date)
            try:
                self.gl.info('CVE retriving: [{}, {}] total: {}'.format(start_date, end_date, total))
                response = requests.get(self.url, params=param, verify=False)
                data = response.json()
                # check error message
                msg = data.get('message')
                if(msg is not None):
                    self.gl.warning('request error: {}'.format(msg))
                    continue
            except requests.exceptions.RequestException as e:
                self.gl.warning('{}, will retry...'.format(e))
                continue
            except json.JSONDecodeError as e:
                self.gl.warning(e)
                self.gl.warning(response)
                continue
            # start handle data
            cur_cve_list = data['result']['CVE_Items']
            count = len(cur_cve_list)
            if(count == 0):
                break
            cve_list.extend(cur_cve_list)
            total += count
            # avoid being treated as Ddos
            time.sleep(3)
        return cve_list

class CPEItem:
    def __init__(self, part, vendor, product) -> None:
        self.part = part
        self.vendor = vendor
        self.product = product

    def __hash__(self) -> int:
        return hash('{}{}{}'.format(self.part, self.vendor, self.product))

    def __eq__(self, cpe_item) -> bool:
        return (self.part == cpe_item.part and
                self.vendor == cpe_item.vendor and
                self.product == cpe_item.product)

class CVEItem:
    def __init__(self, data):
        self.ts = Timestamp()
        self.parse(data)
        self.hash_id = self.get_hash_id(self.cve_id)

    def parse(self, data):
        self.cve_id = data["cve"]["CVE_data_meta"]["ID"]
        # get cve primary key in database
        self.primary_key = self.get_cve_key()
        # get cpe set
        nodes = data.get('configurations', {}).get('nodes', {})
        # cpe set is used to move away duplicate cpes
        self.cpe_set = self.recur_cpe_node(nodes)
        # get cwe set
        self.cwe_set = self.get_cwe_set(data['cve']['problemtype'])
        # get patch list
        self.patch_list = self.get_patch_list(data['cve'].get('references'))
        # set nvd link
        self.link = 'https://nvd.nist.gov/vuln/detail/' + self.cve_id
        # update description
        self.description = data['cve']['description']['description_data'][0]['value']
        # update cvssV2 information, nonexistent field will be set as a default value
        info = data.get('impact', {}).get('baseMetricV2', {})
        self.severity_v2 = info.get('severity')
        info = info.get('cvssV2', {})
        self.score_v2 = info.get('baseScore')
        # update cvssV3 information, nonexistent field will be set as a default value
        info = data.get('impact', {}).get('baseMetricV3', {})
        info = info.get('cvssV3', {})
        self.score_v3 = info.get('baseScore')
        self.severity_v3 = info.get('baseSeverity')
        # get timestamp
        self.published_date = self.ts.get_datetime(data['publishedDate'], '%Y-%m-%dT%H:%MZ')
        self.modified_date = self.ts.get_datetime(data['lastModifiedDate'], '%Y-%m-%dT%H:%MZ')

    def get_hash_id(self, cve_id):
        # CVE-<Year>-<Number>
        return int(self.cve_id.replace('-', '').replace('CVE', ''))

    def get_cve_key(self):
        parts = self.cve_id.split('-')
        year = int(parts[1])
        number = int(parts[2])
        key = year * 10000000000 + number
        return key

    def get_cwe_set(self, problem_type):
        cwe_set = set()
        type_data_list = problem_type.get('problemtype_data', [])
        for type_data in type_data_list:
            desc_list = type_data.get('description', [])
            for desc in desc_list:
                cwe = desc['value'].lower()
                if (cwe.startswith('cwe-')):
                    cwe = cwe.replace('cwe-', '')
                    cwe_set.add(int(cwe))
        return cwe_set

    def get_patch_list(self, refs):
        patch_list = []
        if(refs is None):
            return patch_list
        ref_data = refs.get('reference_data')
        if(ref_data is None):
            return patch_list
        for ref in ref_data:
            if('Patch' in ref.get('tags')):
                patch_list.append(ref.get('url'))
        return patch_list

    def recur_cpe_node(self, nodes):
        cpe_set = set()
        for node in nodes:
            if('cpe_match' in node):
                for cpe in node['cpe_match']:
                    if(cpe['vulnerable'] == False):
                        continue
                    # we only use CPE 2.3
                    c = CPE(cpe['cpe23Uri'])
                    parts = c.get_part()
                    vendors = c.get_vendor()
                    products = c.get_product()
                    for pt, vd, pd in zip(parts, vendors, products):
                        # we need to use percent encoding
                        # vd = urllib.parse.quote(vd.replace('\\', '')).lower()
                        # pd = urllib.parse.quote(pd.replace('\\', '')).lower()
                        # cpe_item = 'cpe:/{}:{}:{}'.format(pt, vd, pd)
                        cpe_item = CPEItem(pt, vd, pd)
                        cpe_set.add(cpe_item)
            if('children' in node):
                sub_cpe_set = self.recur_cpe_node(node['children'])
                cpe_set = cpe_set.union(sub_cpe_set)
        return cpe_set

    def to_json(self):
        data = {}
        data['cve_id'] = self.cve_id
        data['cpe_list'] = self.cpe_list
        data['patch_list'] = self.patch_list
        data['link'] = self.link
        data['description'] = self.description
        data['severity_v2'] = self.severity_v2
        data['score_v2'] = self.score_v2
        data['severity_v3'] = self.severity_v3
        data['score_v3'] = self.score_v3
        data['published_date'] = self.published_date
        data['modified_date'] = self.modified_date
        return data

    def get_cve_info(self):
        cve_info = CVEInfo()
        cve_info.id = self.primary_key
        cve_info.cve_id = self.cve_id
        cve_info.nvd_url = self.link
        cve_info.description = self.description
        cve_info.score_v2 = self.score_v2
        cve_info.severity_v2 = self.severity_v2
        cve_info.score_v3 = self.score_v3
        cve_info.severity_v3 = self.severity_v3
        cve_info.publish = self.published_date
        cve_info.update = self.modified_date
        cve_info.cpes.extend(self.get_cpe_info_list())
        cve_info.cwes.extend(self.get_cwe_info_list())
        return cve_info

    def get_cpe_info_list(self):
        cpe_info_list = list()
        for cpe_item in self.cpe_set:
            cpe_info = CPEInfo()
            cpe_info.part = cpe_item.part
            cpe_info.vendor = cpe_item.vendor
            cpe_info.product = cpe_item.product
            cpe_info_list.append(cpe_info)
        return cpe_info_list

    def get_cwe_info_list(self):
        cwe_info_list = list()
        for cwe in self.cwe_set:
            cwe_info = CWEInfo()
            cwe_info.cwe = cwe
            cwe_info_list.append(cwe_info)
        return cwe_info_list
