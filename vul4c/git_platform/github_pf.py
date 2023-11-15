import base64
import logging
import random
import time
from itertools import takewhile
from pathlib import Path
from typing import Optional
import github
import urllib3.exceptions
from github.Repository import Repository
from urllib.parse import urlparse
import re
from github import Github, Auth, GithubException
from github.Commit import Commit
from github.PaginatedList import PaginatedList
import json
import requests
from string import Template
from urllib3.util.retry import Retry
from vul4c.git_platform.git_platform_base import GitPlatformBase
from typing import Tuple
from github.GithubException import BadCredentialsException
from vul4c.util.utils import check_file_exists_and_not_empty
from vul4c.util.config import config_file
from vul4c.util.logging_util import global_logger
from vul4c.git_platform.common import CommitInfo, try_repo_name_merge, DownloadedCommitInfo, trunc_commit_file_name, \
    try_decode_binary_data_and_write_to_file, cache_commit_file_dir, RawCommitInfo

GITHUB_TOKENS = config_file['github']
GITHUB_LIST = []

# class GitHubRetry(Retry):
#     def get_backoff_time(self):
#         consecutive_errors_len = len(
#             list(
#                 takewhile(lambda x: x.redirect_location is None, reversed(self.history))
#             )
#         )
#         if consecutive_errors_len <= 1:
#             return 0
#
#         backoff_value = self.backoff_factor * (2 ** (consecutive_errors_len - 1))
#         return min(60, backoff_value)

def add_github_token_and_check():
    global GITHUB_LIST,GITHUB_TOKENS
    for token in GITHUB_TOKENS:
        global_logger.info(f'adding GitHub Token {token}')
        GITHUB_LIST.append(Github(token,
                                  retry=Retry(total=None, backoff_factor= 0.1,
                                              status_forcelist=[403],)))  # 403 rate limit exceeded

    for idx,github in enumerate(GITHUB_LIST):
        try:
            github.get_repo('JetBrains/kotlin')
        except BadCredentialsException as e:
            global_logger.error(f'{GITHUB_TOKENS[idx]} GitHub Token has expired.')
            raise e

    global_logger.info(f'Initialize GtiHub instance from {len(GITHUB_TOKENS)} tokens')

add_github_token_and_check()

def random_g() -> Github:
    # get GitHub instance randomly
    idx = random.randint(0, len(GITHUB_LIST) - 1)
    return GITHUB_LIST[idx]


def random_token() -> str:
    idx = random.randint(0, len(GITHUB_TOKENS) - 1)
    return GITHUB_TOKENS[idx]


raw_find_pull_id_from_issue = """{
  repository(owner:"$repo_owner", name:"$repo_name"){
    url
    issue(number: $issue_number){
      state
      timelineItems(last:100,itemTypes:[CROSS_REFERENCED_EVENT,REFERENCED_EVENT,CLOSED_EVENT,CLOSED_EVENT]){
  			totalCount
        nodes{
          __typename
          ... on CrossReferencedEvent{
            id
            createdAt
            isCrossRepository
            source{
              ... on PullRequest{
                number
                id
                url
                state
              }
            }
          }
          ... on ReferencedEvent {
            isCrossRepository
            isDirectReference
            commit {
              url
            }
          }
          ... on ClosedEvent{
            closer{
              __typename
              ... on Commit{
                url
              }
              ... on PullRequest{
                number
                id
                url
                state
              }
            }
          }
        }
      }
    }
  }
}
"""


def format_query_find_pull_id_from_issue(repo: str, issue_number: int):
    repo_owner, name = repo.split('/')
    t = Template(raw_find_pull_id_from_issue)
    res = t.substitute({'repo_owner': repo_owner, 'repo_name': name, 'issue_number': issue_number})
    return res


def find_github_pull_and_commit_from_issue(logger: logging.Logger, repo: str, issue_number: int) -> (
        list[int], list[str]):
    pull_ids = []
    commit_urls = []

    query = format_query_find_pull_id_from_issue(repo, issue_number)
    github_token = random_token()
    retry_cnt = 10
    while retry_cnt > 0:
        retry_cnt -= 1
        try:
            res = requests.post('https://api.github.com/graphql', json={'query': query},
                                headers={'Authorization': f'bearer {github_token}'}, timeout=10)
        except requests.exceptions.RequestException as e:
            print(f'github GraphQL {e}, retry left:{retry_cnt}')
            continue
        if res.status_code != 200:
            continue
        res_content: dict = json.loads(res.content)
        if 'errors' in res_content.keys():  # find error in GraphQL
            break

        issue = res_content['data']['repository']['issue']
        timeline_items = issue['timelineItems']
        total_items_cnt = timeline_items['totalCount']
        if total_items_cnt == 0 or issue['state'] == 'OPEN':  # issue still OPEN, skip!
            break
        # [CrossReferencedEvent, ReferencedEvent, ClosedEvent]
        # 1. we find possible PR or commits from ClosedEvent.
        find_from_close_event = False
        for n in timeline_items['nodes']:
            node_type = n['__typename']
            if node_type == 'ClosedEvent' and n['closer'] is not None:
                closer = n['closer']
                closer_type = closer['__typename']  # [Commit, PullRequest]
                assert closer_type in ['Commit', 'PullRequest']
                if closer_type == 'Commit':
                    commit_urls.append(closer['url'])
                    find_from_close_event = True
                elif closer_type == 'PullRequest':
                    if closer['state'] == 'MERGED':  # PR state: [OPEN, CLOSED, MERGED]
                        pull_ids.append(closer['number'])
                        find_from_close_event = True

        if find_from_close_event:
            break

        # 2. if not found, then find PR or commits from [CrossReferencedEvent, ReferencedEvent]
        for n in timeline_items['nodes']:
            node_type = n['__typename']
            if node_type == 'CrossReferencedEvent':  # get PR
                if n['isCrossRepository']:
                    continue
                # source maybe empty if reference an issue
                if len(n['source']) == 0 or n['source']['state'] != 'MERGED':
                    continue
                pull_ids.append(n['source']['number'])  # PR id
            elif node_type == 'ReferencedEvent':  # get commit
                if not (n['isCrossRepository'] == False and n['isDirectReference'] == True):
                    continue
                commit_urls.append(n['commit']['url'])

        if len(pull_ids) != 0 and len(commit_urls) != 0:
            # if we find PR and commits in an issue, we ony select commits.
            # commits is more specific than PR.
            pull_ids = []

        break

    return pull_ids, commit_urls


def find_github_commits_from_pull(logger: logging.Logger, repo_name: str, pull_id: int):
    commit_urls = []
    try:
        repo = random_g().get_repo(repo_name)
        pull = repo.get_pull(pull_id)
        commits: PaginatedList[Commit] = pull.get_commits()
        for c in commits:
            commit_urls.append(c.html_url)
        return commit_urls
    except GithubException as e:
        if e.status == 404:
            return commit_urls
        logger.error(f'[Github Exception] Get pull info({repo_name}/{pull_id}) with unknown GithubException:{e}')
        raise e


def find_github_commits_from_issue(logger: logging.Logger, repo_name: str, issue_id: int) -> list[str]:
    # it is difficult to locate commits in the comments of issue.
    # e.g. https://github.com/dagolden/Capture-Tiny/issues/16 , https://github.com/chanmix51/Pomm/issues/122 ,
    #      https://github.com/ZeusCart/zeuscart/issues/28 , https://github.com/Yeraze/ytnef/issues/49
    commit_urls = []
    pull_ids, issue_commit_urls = find_github_pull_and_commit_from_issue(logger, repo_name, issue_id)
    commit_urls.extend(issue_commit_urls)
    # print('Pull Ids: ',pull_ids)
    # print('Issue commit URLs: ',issue_commit_urls)
    for pull_id in pull_ids:
        commit_urls.extend(find_github_commits_from_pull(logger, repo_name, pull_id))

    # print('Commit URLs: ',commit_urls)
    return commit_urls



def remove_anchor_query_from_url(url:str) -> str:
    parsed_url = urlparse(url)
    if len(parsed_url.fragment) != 0 or len(parsed_url.query) != 0:
        # remove anchor and query string from URL
        if len(parsed_url.fragment) != 0:
            url = url[: -(len(parsed_url.fragment) + 1)]
        if len(parsed_url.query) != 0:
            url = url[: -(len(parsed_url.query) + 1)]
        parsed_url = urlparse(url)

    # pull commit to commit
    # https://github.com/python/cpython/pull/103993/commits/c120bc2d354ca3d27d0c7a53bf65574ddaabaf3a
    # https://github.com/python/cpython/commit/c120bc2d354ca3d27d0c7a53bf65574ddaabaf3a
    if (pull_commit_match :=re.match(r'https?://github\.com/([\w-]+/[\w-]+)/pull/\d+/commits/([\da-f]+)',url ) ) is not None:
        repo_name = pull_commit_match.group(1)
        commit_hash = pull_commit_match.group(2)
        url = f'https://github.com/{repo_name}/commit/{commit_hash}'

    return url

def make_repo_commit_find_dict(url_list:list[str]) -> dict[str,bool]:
    table = {}
    for url in [remove_anchor_query_from_url(u) for u in url_list]:
        if (commit_match := re.match(r'https?://github\.com/([\w-]+/[\w-]+)/commit/([\da-f]+)', url)) is not None:
            repo_name = commit_match.group(1)
            table[repo_name] = True
    return table

def find_potential_commits_from_github(logger: logging.Logger, url: str, url_list:list[str]) -> list[str]:
    """
        if issue/pr and commit come together, we ony select commit url, and do not crawl through issue/pr.
    """
    url = remove_anchor_query_from_url(url)
    commit_find_dict = make_repo_commit_find_dict(url_list)

    commit_urls = []

    # 1. find commit URL
    if (commit_match := re.match(r'https?://github\.com/([\w-]+/[\w-]+)/commit/([\da-f]+)', url)) is not None:
        commit_urls.append(url)
    # 2. find pull URL, search the commit URL in it
    elif (pull_match := re.match(r'https?://github\.com/([\w-]+/[\w-]+)/pull/([\da-f]+)', url)) is not None:
        repo_name = pull_match.group(1)
        if repo_name in commit_find_dict:   # find commit URL before, skip find commits from pull or issue
            return []
        pull_id = int(pull_match.group(2))
        commit_urls.extend(find_github_commits_from_pull(logger, repo_name, pull_id))
    # 3. issue
    elif (issue_match := re.match(r'https?://github\.com/([\w-]+/[\w-]+)/issues/([\da-f]+)', url)) is not None:
        repo_name = issue_match.group(1)
        if repo_name in commit_find_dict:
            return []
        issue_id = int(issue_match.group(2))
        commit_urls.extend(find_github_commits_from_issue(logger, repo_name, issue_id))
    else:
        pass

    if len(commit_urls) == 0:
        logger.info(f'[Github Commit not found]: {url}')

    return commit_urls


# find_potential_commit_urls_from_github_url(global_logger , 'https://github.com/pypa/pip/issues/425' )

# print(len(read_urls_from_file(StorageLocation.result_dir() / 'dump_url/detail' / "github.com")))
# github_urls = read_urls_from_file(StorageLocation.result_dir() / 'dump_url/detail' / "github.com")
# for x in github_urls:
#     find_potential_commit_urls_from_github_url(global_logger, x)
# multiprocessing_map_data_with_logger(find_potential_commit_urls_from_github_url, github_urls, )

# find_potential_commit_urls_from_github_url(global_logger, 'https://github.com/move-language/move/issues/1059')


def find_commit_from_commit_msg_in_github(repo_name: str, msg: str, regex_match: str | None = None) -> [str]:
    search_result: PaginatedList = random_g().search_commits(query=f'repo:{repo_name} merge:false {msg}')

    candidate_commit = []
    c: Commit
    for c in search_result:
        if (regex_match is not None) and (re.search(regex_match, c.commit.message.lower()) is not None):
            candidate_commit.append(c.html_url)
        elif (regex_match is None) and (msg.lower() in c.commit.message.lower()):
            candidate_commit.append(c.html_url)

    return candidate_commit


class GitHubPlatformBase(GitPlatformBase):
    @property
    def platform_name(self) -> str:
        return 'GitHub'

    def can_handle_this_url(self, logger: logging.Logger, url: str, url_netloc: str) -> bool:
        return url_netloc == 'github.com'

    def extract_repo_full_name_and_commit_hash(self, url: str) -> Optional[Tuple[str, str]]:
        """
            https://github.com/gisle/html-parsssser/commit/b9aae1e43eb2c8e989510187cff0ba3e996f9a4c
            repo_full_name = gisle/html-parsssser
            commit_hash = b9aae1e43eb2c8e989510187cff0ba3e996f9a4c
        """
        pattern = r'http[s]?://github.com/(\S+)/commit/([0-9a-f]+)'
        matchObj = re.match(pattern, url)
        if matchObj is None:
            return None
        repo_full_name = matchObj.group(1)
        commit_hash = matchObj.group(2)
        return repo_full_name, commit_hash

    def get_raw_commit_info(self, logger: logging.Logger, url: str) -> Optional[RawCommitInfo]:
        repo_commit = self.extract_repo_full_name_and_commit_hash(url)
        if repo_commit is None:
            return None
        repo_full_name, commit_hash = repo_commit

        # cache
        # if cache_commit_file_dir(repo_full_name, commit_hash, commit_hash).exists():
        #     return None

        while True:
            try:
                repo = random_g().get_repo(repo_full_name)
                commit = repo.get_commit(commit_hash)
                git_url = commit.html_url
                commit_msg = commit.commit.message
                commit_date = int(commit.commit.author.date.timestamp())
                file_paths = [f.filename for f in commit.files]
                parent_commit_hash = commit.parents[0].sha if len(commit.parents) == 1 else None
                # If we are redirecting from one repo to another, we need to update the repo name
                repo_full_name = repo.full_name
                return RawCommitInfo(
                    repo_full_name, commit_msg, commit_hash, parent_commit_hash,commit_date, file_paths, None, git_url
                )

            except github.UnknownObjectException as e:
                logger.info(self.fmt_msg(f'{repo_full_name}:{commit_hash} commit not found'))
            except github.GithubException as e:
                if e.status == 409:
                    logger.info(self.fmt_msg(f'{repo_full_name}:{commit_hash} repository is empty'))
                # else:
                #     raise e
            except (urllib3.exceptions.ReadTimeoutError,requests.exceptions.RequestException):
                logger.info(self.fmt_msg(f'{repo_full_name}:{commit_hash} read time out, try again'))
                time.sleep(60)
                continue
            break

        logger.debug(self.fmt_msg(f'can not download: {url}'))
        return None

    def safe_repo(self,repo_name:str) -> Repository:
        while True:
            repo = random_g().get_repo(repo_name)
            return repo

    def download_commit_with_save_dir(self, logger:logging.Logger, raw_commit_info: RawCommitInfo, need_download_file_paths: list[str],
                                      download_parent_commit: bool, save_dir: Path) -> list[str]:
        assert raw_commit_info.parent_commit_hash is not None

        repo_name =raw_commit_info.repo_name
        repo : Repository
        while True:
            try:
                repo = random_g().get_repo(repo_name)
                break
            except GithubException:
                continue
        already_download_files = []
        tree_hash = raw_commit_info.parent_commit_hash if download_parent_commit else raw_commit_info.commit_hash

        for f_path in need_download_file_paths:
            trunc_file_name = trunc_commit_file_name(f_path)
            # already downloaded files
            if check_file_exists_and_not_empty(save_dir / trunc_file_name):
                already_download_files.append(f_path)
                continue

            try:
                content = repo.get_contents(f_path, tree_hash)
                if content.encoding != 'base64':
                    logger.debug(self.fmt_msg(f'{repo_name}:{tree_hash} File:{f_path} file encoding is none, trying download from git blob'))
                    # if file size > 1MB , we should download the file from git glob
                    file_content_b = base64.b64decode(repo.get_git_blob(content.sha).content)
                else:
                    file_content_b = content.decoded_content
                try_decode_binary_data_and_write_to_file(file_content_b, save_dir / trunc_file_name)
                already_download_files.append(f_path)
            except github.GithubException as e:
                logger.debug(self.fmt_msg(f'{repo_name}:{tree_hash} File:{f_path} is missing'))
                continue

        return already_download_files

if __name__ == '__main__':

    # github_pf = GitHubPlatform()
    # raw_commit = github_pf.get_raw_commit_info(global_logger,
    #                                        '')
    # print(raw_commit)
    # print(github_pf.resolve_raw_commit_and_download(global_logger,raw_commit))

    print(find_potential_commits_from_github(global_logger, 'https://github.com/kuba--/zip/issues/123', []))
