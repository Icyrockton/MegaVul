import json
import logging
import time
from pathlib import Path
from typing import Optional

import gitlab
import requests
from gitlab.v4.objects import Project

from megavul.git_platform.common import CommitInfo, trunc_commit_file_name, \
    try_decode_binary_data_and_write_to_file, RawCommitInfo
from megavul.util.utils import get_bs4_parsed_html, get_request_in_json, check_file_exists_and_not_empty, \
    get_unix_time_from_git_date_gitlab
import bs4
import re
from megavul.git_platform.git_platform_base import GitPlatformBase
from megavul.util.utils import proxies
from gitlab.exceptions import GitlabGetError
import urllib3.exceptions

session = requests.Session()
if proxies is not None:
    session.proxies = proxies
gl = gitlab.Gitlab(session=session,timeout=30)
GITLAB_COMMIT_THRESHOLD = 10

class GitLabPlatformBase(GitPlatformBase):

    @property
    def platform_name(self) -> str:
        return "GitLab"

    def get_raw_commit_info(self, logger: logging.Logger, url: str) -> Optional[RawCommitInfo]:
        re_result = re.match(r"https://gitlab.com/(?P<owner>.*)/(?P<repo>.*)/-/commit/(?P<commit_hash>.*)", url)
        if re_result is None: return None
        owner =re_result.group('owner')
        repo = re_result.group('repo')
        commit_hash = re_result.group('commit_hash')
        repo_name = f'{owner}/{repo}'

        while True:
            try:
                project: Project = gl.projects.get(repo_name)
                commit = project.commits.get(commit_hash)
                commit_json: dict = commit.asdict()
                parent_commit_hash = commit_json['parent_ids'][0] if len(commit_json['parent_ids']) == 1 else None
                commit_msg = commit_json['message']
                commit_date = get_unix_time_from_git_date_gitlab(commit_json['authored_date'])
                file_paths = []
                for diff in commit.diff(get_all=True):
                    file_paths.append(diff['new_path'])
                git_url = commit_json['web_url']

                return RawCommitInfo(
                    repo_name, commit_msg, commit_hash, parent_commit_hash, commit_date, file_paths, None, git_url
                )
            except GitlabGetError as e:
                logger.info(self.fmt_msg(f'{repo_name}:{commit_hash} {e.error_message}'))
                return None
            except (urllib3.exceptions.MaxRetryError,requests.exceptions.SSLError,urllib3.exceptions.RequestError, requests.exceptions.ConnectionError) as e:
                logger.info(self.fmt_msg(f'{repo_name}:{commit_hash} {url} max retries exceeded or SSL error, retry again '))
                continue

    def download_commit_with_save_dir(self, logger: logging.Logger, raw_commit_info: RawCommitInfo,
                                      need_download_file_paths: list[str], download_parent_commit: bool,
                                      save_dir: Path) -> list[str]:
        repo_name = raw_commit_info.repo_name
        already_download_files = []
        tree_hash = raw_commit_info.parent_commit_hash if download_parent_commit else raw_commit_info.commit_hash
        repo = None

        for f_path in need_download_file_paths:
            trunc_name = trunc_commit_file_name(f_path)
            # cache
            if check_file_exists_and_not_empty(save_dir / trunc_name):
                already_download_files.append(f_path)
                continue
            while True:
                try:
                    if repo is None:
                        repo = gl.projects.get(repo_name)
                    file_content_b = repo.files.raw(f_path, ref=tree_hash)
                    try_decode_binary_data_and_write_to_file(file_content_b, save_dir / trunc_name)
                    already_download_files.append(f_path)
                except GitlabGetError as e:
                    logger.info(self.fmt_msg(f'{repo_name}:{tree_hash} {f_path} {e.error_message}'))
                except (urllib3.exceptions.MaxRetryError, requests.exceptions.SSLError,requests.exceptions.ConnectionError) as e:
                    logger.info(self.fmt_msg(f'{repo_name}:{tree_hash} max retries exceeded or SSL error, retry again'))
                    time.sleep(5)
                    continue
                break

        return already_download_files

    def can_handle_this_url(self, logger: logging.Logger, url: str, url_netloc: str) -> bool:
        return url_netloc == 'gitlab.com'


def find_commits_from_pr_in_gitlab(pr_url: str) -> list[str]:
    assert 'merge_requests' in pr_url
    url_prefix = '/'.join(pr_url.split('/')[:-2])
    def compose_commit_url(commit_hash:str):
        return url_prefix + '/commit/' + commit_hash
    pr_commit_url = pr_url + '/commits.json?page=1&per_page=100'
    pr_commit_json = get_request_in_json(pr_commit_url)
    if 'html' not in pr_commit_json:
        return []
    pr_page = bs4.BeautifulSoup(
        pr_commit_json['html'], 'html.parser'
    )
    commit_urls = []
    for item in pr_page.find_all(class_='commit-row-message item-title js-onboarding-commit-item'):
        commit_hash = item['href'].split('commit_id=')[1]
        commit_urls.append(compose_commit_url(commit_hash))
    if len(commit_urls) > GITLAB_COMMIT_THRESHOLD:   # drop big PR
        return []
    return commit_urls

def find_commits_from_issue_in_gitlab(issue_url : str):
    assert 'issues' in issue_url
    url_prefix = '/'.join(issue_url.split('/')[:-2])
    def compose_commit_url(commit_hash:str):
        return url_prefix + '/commit/' + commit_hash
    def compose_pr_url(pr_id:str):
        return url_prefix + '/merge_requests/' + pr_id
    issue_page = get_bs4_parsed_html(issue_url)
    # print(issue_page)
    if issue_page.find(id='js-issuable-app') is None or issue_page.find(id='js-vue-notes') is None:
        return []
    old_issue_header = json.loads(issue_page.find(id='js-issuable-app').attrs['data-initial'])
    # compatible with official version GitLab
    new_issue_header = json.loads(issue_page.find(id='js-vue-notes').attrs['data-noteable-data'])
    issue_state =   old_issue_header['state']  if 'state' in old_issue_header.keys() else new_issue_header['state']
    if issue_state != 'closed':
        return []

    # gitlab issue content return in JSON format
    # e.g. https://gitlab.gnome.org/GNOME/gimp/-/issues/8230/discussions.json?per_page=100
    issue_content = get_request_in_json(issue_url + '/discussions.json?per_page=100')
    commit_urls = []

    for item in issue_content:
        for note in item['notes']:
            if 'system_note_icon_name' in note and note['system_note_icon_name'] == 'issue-close':
                # note['type'] may be null
                note_text = note['note']
                if 'closed via commit' in note_text:
                    # close issue via commit
                    # e.g. closed via commit 22af0bcfe67c1c86381f33975ca7fdbde6b36b39
                    commit_hash = note_text.split(' ')[3]
                    commit_urls.append(compose_commit_url(commit_hash))
                elif 'closed via merge request' in note_text:
                    # close issue via PR
                    # e.g. closed via merge request !3163
                    pr_id : str = note_text.split(' ')[4]
                    if re.match(r'(^!\d+)|(\d+)',pr_id) is not None:
                        if pr_id.startswith('!'):
                            pr_id = pr_id[1:]
                        commit_urls.extend(find_commits_from_pr_in_gitlab(compose_pr_url(pr_id)))

    if len(commit_urls) > GITLAB_COMMIT_THRESHOLD:   # drop big commits
        return []
    return commit_urls

def find_commits_from_gitlab(url:str) -> list[str]:
    if url.find('#') != -1:
        # https://gitlab.freedesktop.org/dbus/dbus/-/issues/305#note_829128
        url = url[:url.find('#')]
    if url.find('/diffs?commit_id') != -1:
        # https://gitlab.com/libtiff/libtiff/merge_requests/33/diffs?commit_id=6da1fb3f64d43be37e640efbec60400d1f1ac39e
        url = url[:url.find('/diffs?commit_id')]
    commits = []
    if 'issue' in url:
        commits.extend(find_commits_from_issue_in_gitlab(url))
    elif 'merge_requests' in url:
        commits.extend(find_commits_from_pr_in_gitlab(url))
    return commits

# test case
# print(find_commits_from_gitlab('https://gitlab.com/gnutls/gnutls/merge_requests/657'))
# print(find_commits_from_gitlab('https://gitlab.com/redhat/centos-stream/rpms/polkit/-/merge_requests/6/diffs?commit_id=bf900df04dc390d389e59aa10942b0f2b15c531e'))
# print(find_commits_from_gitlab('https://gitlab.com/Shinobi-Systems/Shinobi/-/merge_requests/286'))
# print(find_commits_from_gitlab('https://gitlab.com/francoisjacquet/rosariosis/-/issues/291'))
# print(find_commits_from_gitlab('https://gitlab.com/wireshark/wireshark/-/issues/16887'))
# print(find_commits_from_gitlab('https://gitlab.gnome.org/GNOME/gdk-pixbuf/-/merge_requests/121'))