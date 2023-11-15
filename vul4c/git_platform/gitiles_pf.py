import base64
import logging
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse

from vul4c.git_platform.git_platform_base import GitPlatformBase
from vul4c.git_platform.common import CommitInfo, DownloadedCommitInfo, trunc_commit_file_name, \
    try_decode_binary_data_and_write_to_file, RawCommitInfo
from vul4c.util.logging_util import global_logger
from vul4c.util.utils import gitiles_safe_get_bs4_request, gitiles_safe_get_request, check_file_exists_and_not_empty, \
    get_unix_time_from_git_date_gitiles


class GitilesPlatformBase(GitPlatformBase):
    @property
    def platform_name(self) -> str:
        return "Gitiles"

    def get_raw_commit_info(self, logger: logging.Logger, url: str) -> Optional[RawCommitInfo]:
        base_url = urlparse(url)
        repo_name = base_url.netloc.split('.')[0]
        base_url = f'{base_url.scheme}://{base_url.netloc}'
        gitiles_page = gitiles_safe_get_bs4_request(url)
        commit_table = gitiles_page.find('table')
        if commit_table is None:
            logger.debug(self.fmt_msg(f'{url} missing commit table'))
            return None
        commit_table = commit_table.find_all('tr')
        if len(commit_table) != 5:  # filter multiple parent commit
            logger.debug(self.fmt_msg(f'{url} commit table error'))
            return None

        commit_hash = commit_table[0].td.text
        commit_date = get_unix_time_from_git_date_gitiles(commit_table[1].find_all('td')[-1].text)
        tree_url = f'{commit_table[3].a["href"]}'
        tree_url = f"{'/'.join(tree_url.split('/')[:-2])}/"
        tree_url = f'{base_url}{tree_url}'

        # https://android.googlesource.com/platform/frameworks/base/+/ebc250d16c747f4161167b5ff58b3aea88b37acf/
        # https://android.googlesource.com/platform/frameworks/base/+/{commit_hash}/
        parent_commit_hash = commit_table[4].a.text
        if len(parent_commit_hash) == 0:
            parent_commit_hash = None

        commit_msg = gitiles_page.find('pre', class_='u-pre u-monospace MetadataMessage').text

        diff_tree = gitiles_page.find('ul', class_='DiffTree')
        if diff_tree is None:
            logger.debug(self.fmt_msg(f'{url} missing diff tree'))
            return None
        diff_tree = diff_tree.find_all('li')

        file_paths = []
        for d in diff_tree:
            if d.find('span', class_='DiffTree-action DiffTree-action--add') is not None:
                # this file is added , skip this file.
                continue
            if d.find('span', class_='DiffTree-action DiffTree-action--delete') is not None:
                # this file is deleted , skip this file
                continue
            if d.find('span', class_='DiffTree-action DiffTree-action--rename') is not None:
                # this file is rename from some file, skip this file
                continue
            file_paths.append(d.a.text)

        return RawCommitInfo(
            repo_name, commit_msg, commit_hash, parent_commit_hash,commit_date, file_paths, tree_url, url
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
            download_url = f'{tree_url}{tree_hash}/{f_path}?format=TEXT'
            download_content = gitiles_safe_get_request(download_url)
            if download_content is None:
                logger.debug(self.fmt_msg(f'{raw_commit_info.repo_name}:{tree_hash} {f_path} {download_url} download error or file missing'))
                continue
            while len(download_content) == 0 or download_content is None:
                download_content = gitiles_safe_get_request(download_url)
            file_content_b = base64.b64decode(download_content)
            try_decode_binary_data_and_write_to_file(file_content_b, save_dir / trunc_name)
            already_download_files.append(f_path)

        return already_download_files


    def can_handle_this_url(self, logger: logging.Logger, url: str, url_netloc: str) -> bool:
        return 'googlesource.com' in url


if __name__ == '__main__':
    pf = GitilesPlatformBase()
    # raw_commit_info = pf.get_raw_commit_info(global_logger,"https://chromium.googlesource.com/chromium/src/+/181c7400b2bf50ba02ac77149749fb419b4d4797")
    raw_commit_info = pf.get_raw_commit_info(global_logger,"https://chromium.googlesource.com/v8/v8/+/35b44e5fa8542a64117257465b5810e7afca0e27")
    print(raw_commit_info)
    pf.resolve_raw_commit_and_download(global_logger,raw_commit_info)
