import logging
from pathlib import Path
from typing import Optional

from megavul.git_platform.git_platform_base import GitPlatformBase
from megavul.git_platform.common import trunc_commit_file_name, RawCommitInfo
from megavul.util.logging_util import global_logger
from megavul.util.utils import get_bs4_parsed_html, save_str, get_request_in_text, \
    check_file_exists_and_not_empty, get_unix_time_from_git_date_gitweb
from urllib.parse import urlparse
import unicodedata


def find_gitweb_commits_in_search_page(search_page_url: str) -> list[str]:
    # find search page all commit url
    # https://git.moodle.org/gw?p=moodle.git&a=search&h=HEAD&st=commit&s=MDL-76810
    assert 'a=search' in search_page_url
    base_url = urlparse(search_page_url)
    base_url = f'{base_url.scheme}://{base_url.netloc}'
    search_page = get_bs4_parsed_html(search_page_url)
    commit_links = search_page.find('table', class_='commit_search')
    if commit_links is None:
        return []
    commit_links = commit_links.find_all('td', class_='link')

    commit_urls = []
    for c in commit_links:
        url = f'{base_url}{c.a["href"]}'
        commit_urls.append(url)
    return commit_urls


class GitWebPlatformBase(GitPlatformBase):
    @property
    def platform_name(self) -> str:
        return "GitWeb"

    def get_raw_commit_info(self, logger: logging.Logger, url: str) -> Optional[RawCommitInfo]:
        base_url = urlparse(url)
        base_url = f'{base_url.scheme}://{base_url.netloc}'
        gitweb_page = get_bs4_parsed_html(url)
        object_headers = gitweb_page.find('table', class_='object_header')
        if object_headers is None:
            logger.info(self.fmt_msg(f'{url}: table not found'))
            return None
        object_headers = object_headers.find_all('tr')
        # https://sourceware.org/git/gitweb.cgi?p=glibc.git;a=commitdiff;h=d527c860f5a3f0ed687bd03f0cb464612dc23408
        # some url missing commit hash
        if len(object_headers) != 7:
            logger.info(self.fmt_msg(f'{url}: table len != 7'))
            return None
        commit_hash = object_headers[4].find_all('td')[1].text
        tree_hash = commit_hash
        parent_commit_hash = object_headers[6].find_all('td')[1].text
        commit_date = get_unix_time_from_git_date_gitweb(object_headers[1].find('span',class_='datetime').text)

        # remove tree_hash and commit_hash
        tree_url_prefix, tree_url_postfix = object_headers[5].find('td', class_='link').a['href'].split('?')
        tree_url_postfix = tree_url_postfix.split(';')
        tree_url_postfix = list(filter(lambda s: s.startswith('p='), tree_url_postfix))
        tree_url = f'{base_url}{tree_url_prefix}?{";".join(tree_url_postfix)}'

        # parse diff file
        file_paths = []
        diff_tree = gitweb_page.find('table', class_='diff_tree').find_all('tr')
        for file in diff_tree:
            file_paths.append(file.find('td').a.text)

        commit_msg = unicodedata.normalize('NFKD', gitweb_page.find('div', class_='page_body').text)

        repo_name = ''
        for idx, a in enumerate(gitweb_page.find('div', class_='page_header').find_all('a')[2:]):
            if idx > 0:
                repo_name += '/'
            repo_name += a.text
        repo_name = repo_name.split('.')[0]
        raw_commit_info = RawCommitInfo(
            repo_name, commit_msg, commit_hash, parent_commit_hash, commit_date, file_paths, tree_url, url
        )
        return raw_commit_info


    def download_commit_with_save_dir(self, logger: logging.Logger, raw_commit_info: RawCommitInfo,
                                      need_download_file_paths: list[str], download_parent_commit: bool,
                                      save_dir: Path) -> list[str]:

        already_download_files = []
        tree_url = raw_commit_info.tree_url
        tree_hash = raw_commit_info.parent_commit_hash if download_parent_commit else raw_commit_info.commit_hash

        download_base_url = f'{tree_url};a=blob_plain;hb={tree_hash};'
        for f_path in need_download_file_paths:
            trunc_name = trunc_commit_file_name(f_path)
            # cache
            if check_file_exists_and_not_empty(save_dir / trunc_name):
                already_download_files.append(f_path)
                continue
            download_url = f'{download_base_url}f={f_path}'
            download_content = ''
            while len(download_content) == 0:
                download_content = get_request_in_text(download_url)
            save_str(download_content, save_dir / trunc_name)
            already_download_files.append(f_path)

        return already_download_files

    def can_handle_this_url(self, logger: logging.Logger, url: str, url_netloc: str) -> bool:
        return url_netloc in ['sourceware.org', 'git.videolan.org', 'git.moodle.org', 'git.openssl.org'] \
            or 'git.savannah.gnu.org/gitweb' in url


if __name__ == '__main__':
    pf = GitWebPlatformBase()
    raw_commit_info = pf.get_raw_commit_info(global_logger,"https://git.openssl.org/gitweb/?p=openssl.git;a=commit;h=1b4a8df38fc9ab3c089ca5765075ee53ec5bd66a")
    print(raw_commit_info)
    pf.resolve_raw_commit_and_download(global_logger,raw_commit_info)
