import logging
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse

from vul4c.git_platform.git_platform_base import GitPlatformBase
from vul4c.git_platform.common import CommitInfo, DownloadedCommitInfo, trunc_commit_file_name, RawCommitInfo
from vul4c.util.logging_util import global_logger
from vul4c.util.utils import get_bs4_parsed_html, save_str, get_request_in_text, check_file_exists_and_not_empty, get_unix_time_from_git_date_cgit


class CGitPlatformBase(GitPlatformBase):
    @property
    def platform_name(self) -> str:
        return "CGit"

    def get_raw_commit_info(self, logger: logging.Logger, url: str) -> Optional[RawCommitInfo]:
        base_url = urlparse(url)
        base_url = f'{base_url.scheme}://{base_url.netloc}'
        cgit_page = get_bs4_parsed_html(url)
        if cgit_page.find('div', class_='error'):
            logger.info(self.fmt_msg(f'{url}: repositories not found'))
            return None

        commit_info = cgit_page.find('table', class_='commit-info')

        while (commit_info is None) and (cgit_page.find('div',class_='content') is not None):
            # Sometime the returned page has no commit info table
            logger.info(self.fmt_msg(f'{url}: commit info not found, retrying...'))
            cgit_page = get_bs4_parsed_html(url)
            commit_info = cgit_page.find('table', class_='commit-info')

        if commit_info is None:
            logger.info(self.fmt_msg(f'{url}: commit info is none'))
            return None

        commit_info = commit_info.find_all('tr')
        commit_date = get_unix_time_from_git_date_cgit(commit_info[0].find('td', class_='right').text)
        commit_hash = commit_info[2].a.text
        tree_hash = commit_info[3].a.text
        tree_url = urlparse(f'{base_url}{commit_info[3].a["href"]}')
        tree_url = f'{base_url}{tree_url.path}'
        tree_url = tree_url.replace('/tree/', '/plain/')
        # multiple parent hash?
        parent_commit_hash = commit_info[4].a.text
        if len(parent_commit_hash) == 0:
            parent_commit_hash = None
        commit_msg = cgit_page.find('div', class_='commit-msg').text

        diff_url = cgit_page.find('div', class_='diffstat-header').a['href']
        diff_url = f'{base_url}{diff_url}'
        diff_page = get_bs4_parsed_html(diff_url)
        diff_table = diff_page.find('table', class_='diff')

        while diff_table is None and diff_page.find('div',class_='content') is not None:
            logger.info(self.fmt_msg(f'{url}: diff table is not found, retrying...'))
            diff_page = get_bs4_parsed_html(diff_url)
            diff_table = diff_page.find('table', class_='diff')

        if diff_table is None:
            logger.info(self.fmt_msg(f'{url}: diff table is none'))
            return None

        diff_heads = diff_table.find_all('div', class_='head')
        file_paths = []
        for head in diff_heads:
            file = head.a.text
            file_paths.append(file)

        repo_name = cgit_page.find('td', class_='main').find('a', {'title': True}).text
        repo_name = repo_name.split('.')[0]

        return RawCommitInfo(
            repo_name, commit_msg, commit_hash, parent_commit_hash, commit_date, file_paths, tree_url, url
        )


    def download_commit_with_save_dir(self, logger: logging.Logger, raw_commit_info: RawCommitInfo,
                                      need_download_file_paths: list[str], download_parent_commit: bool,
                                      save_dir: Path) -> list[str]:
        already_download_files = []
        tree_url = raw_commit_info.tree_url
        tree_hash = raw_commit_info.parent_commit_hash if download_parent_commit else raw_commit_info.commit_hash

        for f_path in need_download_file_paths:
            trunc_name = trunc_commit_file_name(f_path)
            # cache
            if check_file_exists_and_not_empty(save_dir / trunc_name):
                already_download_files.append(f_path)
                continue
            download_url = f'{tree_url}{f_path}?id={tree_hash}'
            download_content = ''
            while len(download_content) == 0:
                download_content = get_request_in_text(download_url)
            save_str(download_content, save_dir / trunc_name)
            already_download_files.append(f_path)

        return already_download_files

    def can_handle_this_url(self, logger: logging.Logger, url: str, url_netloc: str) -> bool:
        return (url_netloc in ['git.kernel.org','cgit.freedesktop.org','git.savannah.gnu.org'] and
                'git.savannah.gnu.org/gitweb' not in url)



if __name__ == '__main__':
    pf = CGitPlatformBase()
    # raw_commit_info = pf.get_raw_commit_info(global_logger,"https://cgit.freedesktop.org/poppler/poppler/commit/?id=8284008aa8230a92ba08d547864353d3290e9bf9")
    for i in range(100):
        raw_commit_info = pf.get_raw_commit_info(global_logger,
                                                 "http://git.kernel.org/git/?p=linux/kernel/git/torvalds/linux.git;a=commitdiff;h=62b08083ec3dbfd7e533c8d230dd1d8191a6e813")
        print(raw_commit_info)
    # raw_commit_info = pf.get_raw_commit_info(global_logger,"http://git.savannah.gnu.org/cgit/freetype/freetype2.git/commit/?id=79972af4f0485a11dcb19551356c45245749fc5b")
    # print(raw_commit_info)
    # pf.resolve_raw_commit_and_download(global_logger,raw_commit_info)

