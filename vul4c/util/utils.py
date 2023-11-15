import multiprocessing
import os.path
import shutil
import subprocess
import zipfile
from datetime import datetime
from pathlib import Path
import urllib.request
import urllib.error
from urllib.parse import urlparse
import requests
import json
import time
from bs4 import BeautifulSoup
from marshmallow_dataclass import class_schema
from tree_sitter import Language
from vul4c.util.logging_util import global_logger
from vul4c.util.storage import StorageLocation
from vul4c.util.config import config_file
from typing import Optional

proxies: dict | None = None
opener = urllib.request.build_opener()
if config_file['proxy']['enable']:
    http_proxy = config_file['proxy']['http_url']
    https_proxy = config_file['proxy']['https_url']
    global_logger.debug(f'enable proxy: http:[{http_proxy}] https:[{https_proxy}]')
    proxies = {
        'http': http_proxy,
        'https': https_proxy,
    }
    os.environ['HTTP_PROXY'] = http_proxy
    os.environ['HTTPS_PROXY'] = https_proxy
    proxy_handler = urllib.request.ProxyHandler(proxies)
    opener = urllib.request.build_opener(proxy_handler)


DEPENDENCY_NOT_FOUND_MESSAGE = {
    'node' : 'Node.js not found, please install from https://nodejs.org/ and add to PATH environment variable',
    'tree-sitter' : "tree-sitter not found, see https://tree-sitter.github.io/tree-sitter/creating-parsers installation section "
                    "(npm recommend) to install tree-sitter CLI, and add to PATH environment variable",
    'github-linguist': "github-linguist not found, please install from https://github.com/github-linguist/linguist/tree/master#installation"
}

def load_dependencies(dependencies: dict[str,str]):
    global DEPENDENCY_NOT_FOUND_MESSAGE
    concat_path = ''
    for name,path in dependencies.items():
         concat_path += os.pathsep + path
    os.environ['PATH'] += concat_path
    # check dependency
    for name,path in dependencies.items():
        if not shutil.which(name):
            if name in DEPENDENCY_NOT_FOUND_MESSAGE:
                raise ImportError(DEPENDENCY_NOT_FOUND_MESSAGE[name])
            else:
                raise ImportError(f"dependency {name} path not found in config.yaml")

if 'dependencies' not in config_file:
    raise RuntimeError("dependencies [java, scala, sbt, node, tree-sitter, github-linguist] missing")
else:
    load_dependencies(config_file['dependencies'])


def read_json_from_network(url: str) -> dict:
    content = opener.open(url,timeout=10).read()
    data = json.loads(content)
    return data


def safe_read_json_from_network(url: str, sleep_time: int = 3) -> dict:
    while True:
        try:
            data = read_json_from_network(url)
            return data
        except UnicodeDecodeError as e:
            global_logger.error(f'decode error {e}')
            time.sleep(sleep_time)
        except urllib.error.HTTPError as e:
            if e.code == 403:  # 403 forbidden
                global_logger.error(str(e))
                time.sleep(sleep_time)
        except urllib.error.URLError as e:
            global_logger.error(str(e))
            time.sleep(sleep_time)
        except TimeoutError as e:
            global_logger.error(f'Timeout error: {e}')
            time.sleep(sleep_time)


def read_json_from_local(path: Path) -> dict | list:
    return json.load(path.open(mode='r'))


def save_data_as_json(data, save_path: Path, overwrite=False):
    if save_path.exists() and not overwrite:
        print(f'{save_path} exists, using `overwrite` flag to overwrite this file')
        return
    json.dump(data, save_path.open(mode='w'), indent=4)


def save_str(data: str, save_path: Path):
    save_path.parent.mkdir(parents=True, exist_ok=True)
    with save_path.open(mode='w') as f:
        f.write(data)


def filter_duplicate(data: list) -> list:
    return list(set(data))


def read_urls_from_file(path: Path) -> list[str]:
    return [l.rstrip() for l in path.open(mode='r').readlines()]


def get_final_redirect_url(url: str) -> str:
    # get the final URL from a redirect URL
    while True:
        try:
            res = requests.head(url, proxies=proxies,timeout=10)
            break
        except (requests.exceptions.ReadTimeout, requests.exceptions.ProxyError, requests.exceptions.SSLError,
                requests.exceptions.ChunkedEncodingError):
            continue
        except requests.exceptions.ConnectTimeout:
            time.sleep(10)
            continue
    if res.status_code == 200 or ('Location' not in res.headers.keys()):
        return url
    new_url = res.headers['Location']
    if (res.status_code // 100) == 3:  # recursively uncover redirect url
        return get_final_redirect_url(new_url)
    return new_url


def __safe_get_request(url: str) -> Optional[requests.Response]:
    res: Optional[requests.Response] = None
    retry_cnt = 10
    while retry_cnt > 0:
        retry_cnt -= 1
        try:
            res = requests.get(url, proxies=proxies,timeout=10)
            if res.status_code == 404:
                break
            if res.status_code != 200:
                print(f'{url} status code {res.status_code}, retry left:{retry_cnt}')
                sleep_time = 30 if res.status_code == 429 else 10  # HTTP 429 Too Many Requests response status code
                time.sleep(sleep_time)
                continue
            break
        except (requests.exceptions.ChunkedEncodingError,requests.exceptions.ConnectionError,requests.exceptions.RequestException):
            continue
    return res


def get_bs4_parsed_html(url: str) -> BeautifulSoup:
    res = __safe_get_request(url)
    content = res.text if res is not None else ''
    soup = BeautifulSoup(content, "html.parser")
    return soup


def get_request_in_json(url: str) -> dict | list:
    res = __safe_get_request(url)
    if res is None: return {}
    return json.loads(res.content)


def get_request_in_text(url: str) -> str:
    res = __safe_get_request(url)
    return res.text


def load_from_marshmallow_dataclass_json_file(clazz: type, fp: Path, is_list=True) -> list | dict:
    return class_schema(clazz)().loads(
        fp.open(mode='r').read(), many=is_list
    )


def save_marshmallow_dataclass_to_json_file(clazz: type, fp: Path, data: list | dict):
    schema = class_schema(clazz)()
    is_list = isinstance(data, list)
    with fp.open(mode='w') as f:
        f.write(schema.dumps(data, many=is_list))


def gitiles_safe_get_request(url: str) -> str:
    res_content = ''
    while True:
        responses = __safe_get_request(url)
        if responses is None: return ''
        res_content = responses.text
        if res_content.find('RESOURCE_EXHAUSTED: Resource has been exhausted (e.g. check quota)') != -1:
            continue
        if res_content.find('NOT_FOUND: Requested entity was not found') != -1:
            return ''
        break
    return res_content


def gitiles_safe_get_bs4_request(url: str) -> BeautifulSoup:
    soup = BeautifulSoup(gitiles_safe_get_request(url), "html.parser")
    return soup

def check_file_exists_and_not_empty(fp:Path) -> bool:
    return fp.exists() and os.path.getsize(fp) > 0

def get_unix_time(date_format:str , date:str) -> int:
    git_time = datetime.strptime(date, date_format)
    return int(git_time.timestamp())

def get_unix_time_from_git_date_cgit(date_str:str) -> int:
    """ 2006-05-05 17:04:43 -0700 """
    git_time_format = "%Y-%m-%d %H:%M:%S %z"
    return get_unix_time(git_time_format,date_str)

def get_unix_time_from_git_date_gitiles(date_str:str) -> int:
    """ Thu Mar 19 15:51:55 2015 """
    try:
        return get_unix_time("%a %b %d %H:%M:%S %Y", date_str)
    except ValueError:
        return get_unix_time("%a %b %d %H:%M:%S %Y %z", date_str)

def get_unix_time_from_git_date_gitlab(date_str:str) -> int:
    """ 2021-09-20T11:50:22.001+00:00 """
    git_time_format = "%Y-%m-%dT%H:%M:%S.%f%z"
    return get_unix_time(git_time_format,date_str)

def get_unix_time_from_git_date_gitweb(date_str:str) -> int:
    """ Mon, 9 Feb 2015 19:38:41 +0800 """
    git_time_format = "%a, %d %b %Y %H:%M:%S %z"
    return get_unix_time(git_time_format,date_str)

def convert_to_jvm_proxy(proxy_dict:dict) -> str:
    assert 'http' in proxy_dict and 'https' in proxy_dict
    jvm_args = []
    http_url = urlparse(proxy_dict['http'])
    jvm_args.append(f"-Dhttp.proxyHost={http_url.netloc.split(':')[0]}")
    if http_url.port is not None:
        jvm_args.append(f"-Dhttp.proxyPort={http_url.port}")
    https_url = urlparse(proxy_dict['https'])
    jvm_args.append(f"-Dhttps.proxyHost={https_url.netloc.split(':')[0]}")
    if https_url.port is not None:
        jvm_args.append(f"-Dhttps.proxyPort={https_url.port}")
    return " ".join(jvm_args)


def build_tree_sitter_language(language_name : str, debug_mode = False) -> Language:
    assert language_name in ['c','cpp'], "only support c/cpp right now, you can modified this assertion to add more language"
    # now we only support c/cpp tree-sitter, but you can add more languages
    tree_sitter_name = f'tree-sitter-{language_name}'
    tree_sitter_path = StorageLocation.tree_sitter_dir() / tree_sitter_name
    tree_sitter_so = StorageLocation.result_dir() / 'build' / f'build-{tree_sitter_name}.so'

    if not tree_sitter_path.exists() or not (tree_sitter_path / 'grammar.js').exists():
        raise RuntimeError(f"no tree-sitter source found in {tree_sitter_path}")

    if not tree_sitter_so.exists() or debug_mode:
        if multiprocessing.current_process().name != "MainProcess":
            raise RuntimeError(f"tree-sitter only can build in main process")
        # in debug mode, we build so library every time
        global_logger.info(f'{tree_sitter_name} are in DEBUG mode, will build so library every time.')

        # step.1 generate tree-sitter
        subprocess.call(
            'tree-sitter generate',
            cwd=tree_sitter_path,
            env=os.environ.copy(), shell=True
        )

        # step.2 build so library
        Language.build_library(
            str(tree_sitter_so), [str(tree_sitter_path)]
        )

    if not tree_sitter_so.exists():
        raise RuntimeError(f"{tree_sitter_name} build so library does not exist!")

    return Language(str(tree_sitter_so), language_name)

def compress_directory_to_zip(compress_directory:Path, output_zip_path:Path):
    """
        compress directory

        compress_directory_to_zip(Path("path/to/dir"), Path("path/to/final.zip"))
    """
    shutil.make_archive(
        str(output_zip_path.with_suffix('')),
        'zip',
        compress_directory
    )


if __name__ == '__main__':
    print(get_unix_time_from_git_date_cgit('2006-05-05 17:04:43 -0700'))
    print(get_unix_time_from_git_date_gitlab('2021-09-20T11:50:22.001+00:00'))
    print(get_unix_time_from_git_date_gitweb('Mon, 9 Feb 2015 19:38:41 +0800'))
    # print(safe_read_json_from_network('https://services.nvd.nist.gov/rest/json/cves/2.0/?resultsPerPage=1'))
    print(convert_to_jvm_proxy({'http' : 'http://www.google.com' , 'https' : 'http://www.google.com:1234'}))

    compress_directory_to_zip(Path("/home/icy/PyCharmProjects/Vul4C/vul4c/pipeline"),Path("/home/icy/PyCharmProjects/Vul4C/vul4c/pipeline/hello.zip"))