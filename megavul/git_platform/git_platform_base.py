import logging
from abc import ABCMeta, abstractmethod
from typing import Optional
from megavul.git_platform.common import DownloadedCommitInfo, cache_commit_file_dir, filter_accepted_files, \
    RawCommitInfo
from pathlib import Path


class GitPlatformBase(metaclass=ABCMeta):

    @property
    @abstractmethod
    def platform_name(self) -> str:
        ...

    def fmt_msg(self, msg: str):
        return f'[{self.platform_name}] {msg}'

    @abstractmethod
    def get_raw_commit_info(self, logger: logging.Logger, url: str) -> Optional[RawCommitInfo]:
        ...



    @abstractmethod
    def download_commit_with_save_dir(self, logger: logging.Logger, raw_commit_info: RawCommitInfo,
                                      need_download_file_paths: list[str],
                                      download_parent_commit: bool, save_dir: Path) -> list[str]:
        ...

    def resolve_raw_commit_and_download(self, logger:logging.Logger, raw_commit_info: RawCommitInfo) -> Optional[DownloadedCommitInfo]:
        a_dl_files = self.download_commit(logger , raw_commit_info, False)
        b_dl_files = self.download_commit(logger , raw_commit_info, True)
        # 1. some files are newly added
        # 2. some files are renamed
        # we have no way to track these files.
        if len(set(a_dl_files)) != len(set(b_dl_files)):
            logger.debug(self.fmt_msg(f"{raw_commit_info.repo_name}:{raw_commit_info.commit_hash}"
                                      f" from {raw_commit_info.git_url} has different number of files compared to parent commit."
                                      f" this:{a_dl_files} parent:{b_dl_files}"))

        diff_file_paths = list(set(a_dl_files) & set(b_dl_files))
        if len(diff_file_paths) == 0:
            return None
        return DownloadedCommitInfo(raw_commit_info.repo_name, raw_commit_info.commit_msg,
                                    raw_commit_info.commit_hash, raw_commit_info.parent_commit_hash,raw_commit_info.commit_date,
                                    diff_file_paths, raw_commit_info.git_url
                                    )

    def download_commit(self, logger: logging.Logger, raw_commit_info: RawCommitInfo, download_parent_commit: bool) -> list[str]:
        save_dir = cache_commit_file_dir(raw_commit_info.repo_name, raw_commit_info.commit_hash,
                                         raw_commit_info.parent_commit_hash) if download_parent_commit else (
            cache_commit_file_dir(raw_commit_info.repo_name, raw_commit_info.commit_hash, raw_commit_info.commit_hash))

        need_download_file_paths = filter_accepted_files(raw_commit_info.file_paths)

        return self.download_commit_with_save_dir(logger,raw_commit_info, need_download_file_paths, download_parent_commit, save_dir)

    @abstractmethod
    def can_handle_this_url(self, logger: logging.Logger, url: str, url_netloc: str) -> bool:
        """ Check this Git platform can handle this URL """
        ...



class FallBackPlatformBase(GitPlatformBase):
    @property
    def platform_name(self) -> str:
        return "FallBack"

    def get_raw_commit_info(self, logger: logging.Logger, url: str) -> Optional[RawCommitInfo]:
        pass

    def resolve_raw_commit_and_download(self, logger: logging.Logger, raw_commit_info: RawCommitInfo) -> Optional[
        DownloadedCommitInfo]:
        pass

    def download_commit_with_save_dir(self, logger: logging.Logger, raw_commit_info: RawCommitInfo,
                                      need_download_file_paths: list[str], download_parent_commit: bool,
                                      save_dir: Path) -> list[str]:
        pass

    def can_handle_this_url(self, logger: logging.Logger, url: str, url_netloc: str) -> bool:
        logger.info(self.fmt_msg(f'No GitPlatform can handle: {url}'))
        return True