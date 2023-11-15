import json
import math
from tqdm import tqdm
from dataclasses import dataclass

from vul4c.pipeline.json_save_location import all_cve_from_nvd_json_path
from vul4c.util.utils import  safe_read_json_from_network , read_json_from_local , save_data_as_json
from vul4c.util.logging_util import global_logger
from vul4c.util.storage import StorageLocation

RESULT_PER_PAGE = 1000
def compose_nvd_page_url(page_index: int, results_per_page: int = RESULT_PER_PAGE):
    return f'https://services.nvd.nist.gov/rest/json/cves/2.0/?resultsPerPage={results_per_page}&startIndex={page_index * RESULT_PER_PAGE}'

@dataclass
class NvdMetaData:
    totalResults : int
    version : str

def get_nvd_metadata() -> NvdMetaData:
    """
        get the number of total results in the NVD database, and version number
    """
    first_page_url = compose_nvd_page_url(page_index= 0 , results_per_page=1)
    data = safe_read_json_from_network(first_page_url)
    # ['resultsPerPage', 'startIndex', 'totalResults', 'format', 'version', 'timestamp', 'vulnerabilities']
    metadata = NvdMetaData(data['totalResults'] , data['version'])
    return metadata


def crawl_nvd(use_cache:bool = True):
    nvd_metadata = get_nvd_metadata()
    total_page_cnt = math.ceil(nvd_metadata.totalResults / RESULT_PER_PAGE)
    result_save_path = all_cve_from_nvd_json_path
    cache_page_dir = StorageLocation.create_cache_dir('nvd_page_cache')

    global_logger.info(f'begin crawl CVE entries from NVD database, total entries:{nvd_metadata.totalResults}, total pages:{total_page_cnt}')
    all_cve_entries = []

    if result_save_path.exists():
        old_result_entries_cnt = len(json.load(result_save_path.open(mode='r')))
        if old_result_entries_cnt == nvd_metadata.totalResults and use_cache:
            global_logger.info(
                f'{result_save_path} exists, all CVE entries({nvd_metadata.totalResults}) from NVD databases has been downloaded before!')
            return
        elif old_result_entries_cnt != nvd_metadata.totalResults:
            global_logger.info(f'out-of-date data, old:{old_result_entries_cnt} now:{nvd_metadata.totalResults}, try to download the latest NVD database')
        else:
            global_logger.info(f'try to download the latest NVD database, ignoring the cache')


    # begin download latest CVE entries from NVD databases
    for page in tqdm(range(total_page_cnt),desc='Downloading CVE page from NVD',):
        cache_page_path = cache_page_dir / f'{RESULT_PER_PAGE}_{page}.json'
        if cache_page_path.exists() and use_cache:
            global_logger.debug(f'{page} page using cache from {cache_page_path}')
            all_cve_entries.extend(read_json_from_local(cache_page_path))
            continue

        page_url = compose_nvd_page_url(page,RESULT_PER_PAGE)
        data: dict
        cve_entries: list
        while True:
            data = safe_read_json_from_network(page_url,15)
            cve_entries = [item['cve'] for item in data['vulnerabilities']]
            expected_entries_len = RESULT_PER_PAGE if (page < total_page_cnt - 1) else  nvd_metadata.totalResults % RESULT_PER_PAGE
            if expected_entries_len != len(cve_entries):
                global_logger.warning(f'download data incomplete, expected entries length:{expected_entries_len} but download:{len(cve_entries)}, trying again...')
                continue
            break

        all_cve_entries.extend(cve_entries)
        save_data_as_json(cve_entries, cache_page_path)

    global_logger.info(f'download NVD database complete! total entries:{len(all_cve_entries)}')
    save_data_as_json(all_cve_entries,result_save_path)

if __name__ == '__main__':
    crawl_nvd()
