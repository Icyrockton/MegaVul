import dataclasses
import logging
from multiprocessing import current_process
from megavul.git_platform.cgit_pf import CGitPlatformBase
from megavul.git_platform.github_pf import GitHubPlatformBase
from megavul.git_platform.git_platform_base import GitPlatformBase, FallBackPlatformBase
from megavul.git_platform.gitiles_pf import GitilesPlatformBase
from megavul.git_platform.gitlab_pf import GitLabPlatformBase
from megavul.git_platform.gitweb_pf import GitWebPlatformBase
from megavul.pipeline.json_save_location import cve_with_downloaded_commit_json_path, cve_with_reference_url_json_path
from megavul.util.concurrent_util import multiprocessing_apply_data_with_logger
from megavul.util.logging_util import global_logger
from megavul.git_platform.common import CveWithReferenceUrl, DownloadedCommitInfo, try_repo_name_merge, \
    CveWithDownloadedCommitInfo
from megavul.util.utils import load_from_marshmallow_dataclass_json_file, save_marshmallow_dataclass_to_json_file
from urllib.parse import urlparse

def run_git_platform_pipeline(logger: logging.Logger,
                              cve_with_reference_url: list[CveWithReferenceUrl]) -> list[CveWithDownloadedCommitInfo]:
    process_name = current_process().name
    logger.info(f'{process_name} begin process {len(cve_with_reference_url)} CVE entries')
    report_progress_step = int(len(cve_with_reference_url) * 0.1)
    git_pfs: list[GitPlatformBase] = [
        GitHubPlatformBase(),
        GitLabPlatformBase(),
        GitWebPlatformBase(),
        CGitPlatformBase(),
        GitilesPlatformBase(),
        FallBackPlatformBase()
    ]
    cve_with_commit: list[CveWithDownloadedCommitInfo] = []

    for idx, cve in enumerate(cve_with_reference_url):
        if idx % report_progress_step == 0 and idx > 0:
            logger.info(f'{process_name} processed [{idx}/{len(cve_with_reference_url)}] CVE entries')

        cve_resolve_commits: list[DownloadedCommitInfo] = []

        for ref_url in cve.reference_urls:
            ref_url_netloc = urlparse(ref_url).netloc
            # run pipeline
            for git_pf in git_pfs:
                if git_pf.can_handle_this_url(logger, ref_url, ref_url_netloc):
                    raw_commit = git_pf.get_raw_commit_info(logger, ref_url)
                    if raw_commit is None or raw_commit.parent_commit_hash is None:
                        break

                    resolve_commit = git_pf.resolve_raw_commit_and_download(logger, raw_commit)
                    if resolve_commit is None:
                        break

                    need_add_to_result = True
                    need_remove_pre = None
                    for pre_commit in cve_resolve_commits:
                        pre_commit_repo_name = try_repo_name_merge(pre_commit.repo_name)
                        this_commit_repo_name = try_repo_name_merge(resolve_commit.repo_name)

                        if pre_commit.commit_hash == resolve_commit.commit_hash:
                            # commit duplicate
                            logger.info(
                                f'find duplicate commits, {pre_commit.repo_name}:{pre_commit.commit_hash}:{pre_commit.git_url}'
                                f' -> {resolve_commit.repo_name}:{resolve_commit.commit_hash}:{resolve_commit.git_url}')
                            if len(pre_commit_repo_name) <= len(this_commit_repo_name):
                                # save the commit with the minimum length of the repo name.
                                need_add_to_result = False
                            else:
                                need_remove_pre = pre_commit

                    if need_remove_pre is not None:
                        cve_resolve_commits.remove(need_remove_pre)

                    if need_add_to_result:
                        cve_resolve_commits.append(resolve_commit)

                    break

        if len(cve_resolve_commits) != 0:
            cve_without_reference = dataclasses.asdict(cve)
            cve_without_reference.pop('reference_urls')
            # only update `commits` field
            new_cve = CveWithDownloadedCommitInfo(
                commits=cve_resolve_commits, **cve_without_reference
            )
            cve_with_commit.append(new_cve)

    return cve_with_commit


def commit_website_statistic(cve_with_reference_url: list[CveWithReferenceUrl]):
    netloc_set = {}
    for cve in cve_with_reference_url:
        for netloc in [urlparse(url).netloc for url in cve.reference_urls]:
            netloc_set.setdefault(netloc, 0)
            netloc_set[netloc] += 1

    netloc_cnt_info = "\nCommit Statistical Info In Different Websites\n"
    for netloc, cnt in sorted(netloc_set.items(), key=lambda x: x[1], reverse=True):
        netloc_cnt_info += f'{netloc:>30}: {cnt}\n'
    global_logger.info(netloc_cnt_info)


def extract_and_download_commit():
    cve_with_reference_url: list[CveWithReferenceUrl] = load_from_marshmallow_dataclass_json_file(
        CveWithReferenceUrl, cve_with_reference_url_json_path)

    global_logger.info(f'Begin download commits from commit url, total CVE entries: {len(cve_with_reference_url)}')
    commit_website_statistic(cve_with_reference_url)

    downloaded_commit_cves = (
        multiprocessing_apply_data_with_logger(run_git_platform_pipeline, cve_with_reference_url, chunk_mode=True))

    global_logger.info(f'Successfully download commits from {len(downloaded_commit_cves)} CVE entries')
    global_logger.info(f'Save CveWithDownloadedCommitInfo to {cve_with_downloaded_commit_json_path}')
    save_marshmallow_dataclass_to_json_file(CveWithDownloadedCommitInfo, cve_with_downloaded_commit_json_path, downloaded_commit_cves)

if __name__ == '__main__':
    extract_and_download_commit()
