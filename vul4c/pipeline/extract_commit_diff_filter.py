import logging
from abc import ABCMeta, abstractmethod
from dataclasses import asdict
from vul4c.git_platform.common import CveWithCommitInfo, VulnerableFunction, NonVulnerableFunction, CommitFile, \
    CommitInfo
from typing import Callable, List, Tuple
from vul4c.util.logging_util import global_logger
import wordsegment
from dataclasses import dataclass

# load wordsegment corpus
wordsegment.load()

def update_commit_info_with_files(old_commit: CommitInfo, new_files: list[CommitFile]) -> CommitInfo:
    old_commit = asdict(old_commit)
    old_commit.pop('files')
    return CommitInfo(**old_commit, files=new_files)


def update_cve_with_commits(old_cve: CveWithCommitInfo, new_commits: list[CommitInfo]) -> CveWithCommitInfo:
    old_cve = asdict(old_cve)
    old_cve.pop('commits')
    return CveWithCommitInfo(**old_cve, commits=new_commits)


def update_file_with_funcs(old_file: CommitFile, new_vul_funcs: list[VulnerableFunction],
                           new_non_vul_funcs: list[NonVulnerableFunction]) -> CommitFile:
    old_file = asdict(old_file)
    old_file.pop('vulnerable_functions')
    old_file.pop('non_vulnerable_functions')
    return CommitFile(**old_file, vulnerable_functions=new_vul_funcs, non_vulnerable_functions=new_non_vul_funcs)


def iterate_all_cve(logger: logging.Logger, cve_list: list[CveWithCommitInfo],
                    vul_filter: Callable[[VulnerableFunction], bool],
                    non_vul_filter: Callable[[NonVulnerableFunction], bool]):
    result_cve = []
    for cve in cve_list:
        commit_infos = []
        for commit in cve.commits:
            new_files = []
            for file in commit.files:
                new_vul_funcs, new_non_vul_funcs = [], []
                for func in file.vulnerable_functions:
                    if not vul_filter(func):
                        new_vul_funcs.append(func)
                for func in file.non_vulnerable_functions:
                    if not non_vul_filter(func):
                        new_non_vul_funcs.append(func)
                if len(new_vul_funcs) != 0:
                    new_files.append(
                        CommitFile(file.file_name, file.file_path, file.language, new_vul_funcs,
                                   new_non_vul_funcs)
                    )
            if len(new_files) != 0:
                commit_infos.append(
                    update_commit_info_with_files(commit, new_files)
                )
        if len(commit_infos) != 0:
            result_cve.append(update_cve_with_commits(cve, commit_infos))
    return result_cve


class FilterBase(metaclass=ABCMeta):
    DEBUG = False

    def __init__(self, logger: logging.Logger):
        self.__logger = logger

    def _info(self, msg: str):
        if FilterBase.DEBUG:
            self.__logger.info(f'[{self.filter_name}] {msg}')

    @property
    def filter_name(self) -> str:
        return self.__class__.__name__


class GlobalFilter(FilterBase, metaclass=ABCMeta):
    """
        Global filter will first iterate all cve to record some information, and then use the information to filter functions.
        If you don't need to traverse all cve to record some information in advance, recommended to use *LocalFilter*
    """

    @abstractmethod
    def filter(self, cve_list: list[CveWithCommitInfo]) -> list[CveWithCommitInfo]:
        ...


class LocalFilter(FilterBase, metaclass=ABCMeta):
    @abstractmethod
    def filter_vul(self, vul_func: VulnerableFunction) -> bool:
        """ return True if the function should be filtered """
        ...

    @abstractmethod
    def filter_non_vul(self, non_vul_func: NonVulnerableFunction) -> bool:
        ...


class FilterProcessRecorder:
    @dataclass
    class CountInfo:
        vul_func_cnt: int
        no_vul_func_cnt: int
        file_cnt: int
        commit_cnt: int
        cve_cnt: int

    def __init__(self):
        self.prev_info: None | FilterProcessRecorder.CountInfo = None
        self.info: None | FilterProcessRecorder.CountInfo = None

    def record_info(self, cve_with_parsed_commit: list[CveWithCommitInfo]):
        self.prev_info = self.info
        info = self.CountInfo(0, 0, 0, 0, 0)
        self.info = info
        assert self.info is not None
        info.cve_cnt = len(cve_with_parsed_commit)
        for cve in cve_with_parsed_commit:
            info.commit_cnt += len(cve.commits)
            for commit in cve.commits:
                info.file_cnt += len(commit.files)
                for file in commit.files:
                    info.vul_func_cnt += len(file.vulnerable_functions)
                    info.no_vul_func_cnt += len(file.non_vulnerable_functions)

    def print_diff_info(self, logger: logging.Logger, filter_name: str | None = None):
        info: FilterProcessRecorder.CountInfo = self.info
        prev_info: FilterProcessRecorder.CountInfo | None = self.prev_info

        def cal_diff(prev: int, cur: int):
            if prev == cur:
                return ""
            elif prev > cur:
                return f"[-{prev - cur}]"
            else:
                return f"[+{cur - prev}]"

        if prev_info is None:
            logger.info(
                f'[Filter Recorder] Before Run All Filters: '
                f'CVE:{info.cve_cnt} Commits:{info.commit_cnt} Files:{info.file_cnt} '
                f'Vul-Functions:{info.vul_func_cnt} Non-Vul-Functions:{info.no_vul_func_cnt}')
        else:
            logger.info(
                f'[Filter Recorder] After {filter_name}: '
                f'CVE:{info.cve_cnt}{cal_diff(prev_info.cve_cnt, info.cve_cnt)} '
                f'Commits:{info.commit_cnt}{cal_diff(prev_info.commit_cnt, info.commit_cnt)} '
                f'Files:{info.file_cnt}{cal_diff(prev_info.file_cnt, info.file_cnt)} '
                f'Vul-Functions:{info.vul_func_cnt}{cal_diff(prev_info.vul_func_cnt, info.vul_func_cnt)} '
                f'Non-Vul-Functions:{info.no_vul_func_cnt}{cal_diff(prev_info.no_vul_func_cnt, info.no_vul_func_cnt)}')

    def record_and_print(self, logger: logging.Logger, cve_with_parsed_commit: list[CveWithCommitInfo],
                         filter_name: str | None = None):
        self.record_info(cve_with_parsed_commit)
        self.print_diff_info(logger, filter_name)


############################################################################################################
##################################### GLOBAL FILTER ########################################################


class TestFileFilter(GlobalFilter):
    """
        filter test file e.g. tests/unittests/tests-clif/tests-clif.c
    """

    def should_filter_this_file(self, file: CommitFile) -> bool:
        file_path = file.file_path

        for path in reversed(file_path.split('/')):
            lower_path = path.split('.')[0]  # remove extension
            lower_path = lower_path.lower()
            if lower_path == 'test' or lower_path == 'tests' or lower_path == 'testing' or lower_path == 'testsuite':
                return True

            split_lower_path = lower_path.split('_')
            if len(split_lower_path) > 1:
                for seg in split_lower_path:
                    if 'test' in seg:
                        return True

            split_lower_path = lower_path.split('-')
            if len(split_lower_path) > 1:
                for seg in split_lower_path:
                    if 'test' in seg:
                        return True

            split_lower_path = wordsegment.segment(lower_path)  # using wordsegment library
            if len(split_lower_path) > 1:
                for seg in split_lower_path:
                    if seg in ['test', 'tests', 'runtest']:
                        return True

        return False

    def filter(self, cve_list: list[CveWithCommitInfo]) -> list[CveWithCommitInfo]:
        result_cve = []

        for cve in cve_list:
            commit_infos = []
            # global_logger.debug(f'{cve.cve_id} {cve.cwe_ids}')
            for commit in cve.commits:
                new_files = []
                for file in commit.files:
                    # global_logger.debug(f'{commit.git_url} {file.file_path}')
                    if not self.should_filter_this_file(file):
                        new_files.append(file)
                    else:
                        self._info(f'find test file {file.file_path} in {commit.git_url}')

                if len(new_files) != 0:
                    commit_infos.append(update_commit_info_with_files(commit, new_files))

            if len(commit_infos) != 0:
                result_cve.append(update_cve_with_commits(cve, commit_infos))
        return result_cve


class MultiCveCommitFilter(GlobalFilter):
    """
        filter some commit across multiple cves.
        https://github.com/rdesktop/rdesktop/commit/4dca546d04321a610c1835010b5dad85163b65e1
        this commit has multiple cve.
        CVE-2018-8791, CVE-2018-8792, CVE-2018-8793, CVE-2018-8794, CVE-2018-8795, CVE-2018-8796, CVE-2018-8797 ... ...
        we only keep one CVE(first appear) and gather all CWE ids in it.
        todo what about other cvss metrics?
    """

    def commit_key(self, commit: CommitInfo):
        return f"{commit.repo_name}$$${commit.commit_hash}"

    def filter(self, cve_list: list[CveWithCommitInfo]) -> list[CveWithCommitInfo]:
        result_cve = []
        commit_occur_table: dict[str, tuple[int, set]] = {}

        for cve in cve_list:
            commit_infos = []
            for commit in cve.commits:
                commit_key = self.commit_key(commit)
                commit_occur_table.setdefault(commit_key, (0, set()))  # default value

                (occurrence_count, cwe_set) = commit_occur_table[commit_key]
                cwe_set.update(cve.cwe_ids)

                if occurrence_count == 0:
                    commit_infos.append(commit)  # add this commit, drop other commit if they appear in other cve
                else:
                    self._info(f'find commit in multiple cve, {commit.git_url} found in {cve.cve_id}')

                commit_occur_table[commit_key] = (occurrence_count + 1, cwe_set)

            if len(commit_infos) != 0:
                result_cve.append(update_cve_with_commits(cve, commit_infos))

        cve_list = result_cve
        result_cve = []
        # update `cwe_list`
        for cve in cve_list:
            commit_infos = []
            need_update_cwe = False
            new_cwe_list = []
            for commit in cve.commits:
                commit_key = self.commit_key(commit)
                (occurrence_count, cwe_set) = commit_occur_table[commit_key]
                if occurrence_count > 1:
                    need_update_cwe = True
                    new_cwe_list.extend(cwe_set)

            if need_update_cwe:
                cve_dict = asdict(cve)
                cve_dict.pop('cwe_ids')
                cve_dict.pop('commits')
                result_cve.append(
                    CveWithCommitInfo(**cve_dict, cwe_ids=list(set(new_cwe_list)), commits=cve.commits)
                )
            else:
                result_cve.append(cve)

        return result_cve


class OneCveMultipleCommitsNonVulDuplicateFilter(GlobalFilter):
    """
        some cve have multiple commits to fix the vulnerability, with each commit making minor changes to the function.
        non-vul funcs keep unchanged, but we extract them in each commit,
        and there are many redundant duplicate non-vul that we need to filter out.

        e.g.CVE-2018-19535
Exiv2/exiv2:8b480bc5b2cc2abb8cf6fe4e16c24e58916464d2  files=[file_name=pngchunk_int.cpp, vul_funcs=[PngChunk::readRawProfile], non_vul_funcs=[PngChunk::parseTXTChunk... ...
Exiv2/exiv2:cf3ba049a2792ec2a4a877e343f5dd9654da53dc  files=[file_name=pngchunk_int.cpp, vul_funcs=[PngChunk::readRawProfile], non_vul_funcs=[PngChunk::parseTXTChunk... ...
Exiv2/exiv2:03173751b4d7053d6ddf52a15904e8f751f78f56  files=[file_name=pngchunk_int.cpp, vul_funcs=[PngChunk::readRawProfile], non_vul_funcs=[PngChunk::parseTXTChunk... ...
    """

    def filter(self, cve_list: list[CveWithCommitInfo]) -> list[CveWithCommitInfo]:
        result_cve = []

        for cve in cve_list:

            # fast path
            if len(cve.commits) <= 1:
                result_cve.append(cve)
                continue

            # { file_A : [hash1, hash2, hash3] , file_B : [hash1, hash2, hash3]  }
            file_in_commits: dict[str, list] = {}

            for commit in cve.commits:

                for file in commit.files:
                    file_in_commits.setdefault(file.file_path, [])
                    file_in_commits[file.file_path].append(commit.commit_hash)

            cve_commits = cve.commits
            # self._info(f'[Before] {cve.cve_id}')
            # for c in cve_commits:
            #     self._info(f'{c}')

            for file_path, commit_hash_list in file_in_commits.items():
                # get intersect all non-vul funcs name

                non_vul_funcs_intersect_key = set()

                for commit in cve_commits:
                    if commit.commit_hash not in commit_hash_list:
                        continue

                    for file in commit.files:
                        if file_path != file.file_path:
                            continue
                        non_vul_func_keys = [f"{f.func_name}$$${f.parameter_list_signature}" for f in
                                             file.non_vulnerable_functions]
                        if len(non_vul_funcs_intersect_key) == 0:
                            non_vul_funcs_intersect_key.update(non_vul_func_keys)
                        else:
                            non_vul_funcs_intersect_key = non_vul_funcs_intersect_key & set(non_vul_func_keys)
                # self._info(f'non_vul_funcs_intersect_key: {non_vul_funcs_intersect_key}')
                # todo check the func content is same, otherwise remove the function from set

                # remove the non-vul in file, keep only one commit has it.
                need_remove = False
                new_commits = []
                for commit in cve_commits:
                    if commit.commit_hash not in commit_hash_list:
                        new_commits.append(commit)
                        continue

                    new_files = []
                    for file in commit.files:
                        if file_path != file.file_path:
                            new_files.append(file)
                            continue
                        if not need_remove:
                            need_remove = True
                            new_files.append(file)
                            continue

                        new_non_vul_funcs = list(filter(lambda
                                                            x: f'{x.func_name}$$${x.parameter_list_signature}' not in non_vul_funcs_intersect_key,
                                                        file.non_vulnerable_functions))
                        file_dict = asdict(file)
                        file_dict.pop('non_vulnerable_functions')
                        file_dict.pop('vulnerable_functions')
                        new_files.append(
                            CommitFile(**file_dict, non_vulnerable_functions=new_non_vul_funcs,
                                       vulnerable_functions=file.vulnerable_functions)
                        )

                    new_commits.append(update_commit_info_with_files(commit, new_files))

                cve_commits = new_commits

            result_cve.append(update_cve_with_commits(cve, cve_commits))
        return result_cve


class OneCveMultipleCommitsByContentDuplicateFilter(GlobalFilter):
    """
        some cve's have different commits to fix the vulnerability, these commits have different hash but the content is the same.
        (i.e. for different branch or version or code-base fix)

        e.g. CVE-2015-1242, CVE-2015-2331, CVE-2015-2301, CVE-2022-45332...
https://chromium.googlesource.com/v8/v8/+/0902b5f4dfdea599bf3d96fb9fb258904aff84ec
https://chromium.googlesource.com/v8/v8/+/35b44e5fa8542a64117257465b5810e7afca0e27
    """

    def filter(self, cve_list: list[CveWithCommitInfo]) -> list[CveWithCommitInfo]:
        result_cve = []

        for cve in cve_list:
            # global_logger.debug(f'{cve.cve_id} {cve.cwe_ids}')
            # fast path
            if len(cve.commits) <= 1:
                result_cve.append(cve)
                continue

            # check file first
            all_commit_file_equal = True
            for idx, commit in enumerate(cve.commits):
                if idx == 0:
                    continue
                prev_commit = cve.commits[idx - 1]

                # if commit msg is same, we also consider it equal
                if commit.commit_msg == prev_commit.commit_msg and len(commit.commit_msg) != 0:
                    continue

                this_file_set = set([f.file_path for f in commit.files])
                prev_file_set = set([f.file_path for f in prev_commit.files])
                if this_file_set != prev_file_set:  # file path changed, they must have different content
                    all_commit_file_equal = False
                    break

                # check file content = check vulnerable func
                f: CommitFile
                pre_f: CommitFile
                for f, pre_f in zip(commit.files, prev_commit.files):
                    if len(f.vulnerable_functions) != len(pre_f.vulnerable_functions):
                        all_commit_file_equal = False
                        break

                    content_is_equal = True
                    diff_is_equal = True

                    func: VulnerableFunction
                    for func, pre_func in zip(f.vulnerable_functions, pre_f.vulnerable_functions):
                        if func.func_before != pre_func.func_before or func.func_after != pre_func.func_after:
                            content_is_equal = False

                        # compare diff line, diff level compare
                        if len(func.diff_line_info['deleted_lines']) != len(pre_func.diff_line_info['deleted_lines']) \
                                or len(func.diff_line_info['added_lines']) != len(
                            pre_func.diff_line_info['added_lines']):
                            diff_is_equal = False
                        else:
                            line_names = ['deleted_lines', 'added_lines']
                            for line_name in line_names:
                                for line_a, line_b in zip(func.diff_line_info[line_name],
                                                          pre_func.diff_line_info[line_name]):
                                    if line_a != line_b:
                                        diff_is_equal = False

                    if not content_is_equal and not diff_is_equal:
                        all_commit_file_equal = False
                    elif not content_is_equal and diff_is_equal:
                        # diff info is equal, we consider these commits is equal too (for different version codebase)
                        pass

                    if not all_commit_file_equal:
                        break

            if all_commit_file_equal:
                # only keep one commit in cve
                self._info(f'find duplicate commit in {cve.cve_id}')
                for commit in cve.commits:
                    self._info(f'{commit}')

                result_cve.append(
                    update_cve_with_commits(cve, [cve.commits[0]])
                )
            else:
                result_cve.append(cve)

        return result_cve


class LargeChangeFilter(GlobalFilter):
    """
        some cve have very large number of commits, e.g. CVE-2022-35164
        commit contains large changes, usually contain refactoring, multi-CVE fixes e.g. CVE-2018-17427
    """
    Commit_Count_Threshold = 3
    Commit_Line_Change_Threshold = 110

    def is_large_change_commit(self, commit: CommitInfo) -> bool:
        line_change_cnt = 0
        for file in commit.files:
            for func in file.vulnerable_functions:
                line_change_cnt += len(func.diff_line_info['deleted_lines']) + len(func.diff_line_info['added_lines'])
        return line_change_cnt > LargeChangeFilter.Commit_Line_Change_Threshold

    def filter(self, cve_list: list[CveWithCommitInfo]) -> list[CveWithCommitInfo]:
        result_cve = []

        for cve in cve_list:
            commit_infos = []
            repo_name_cnt: dict[str, int] = {}

            large_change_repo_name = set()
            for commit in cve.commits:
                repo_name = commit.repo_name
                repo_name_cnt.setdefault(repo_name, 0)
                repo_name_cnt[repo_name] += 1

                # step1. remove large change commit
                if self.is_large_change_commit(commit):
                    self._info(f'{cve.cve_id} {commit.git_url} find large change commit')
                    large_change_repo_name.add(repo_name)
                else:
                    commit_infos.append(commit)

            # step2. remove cve's large number of commits by their repo name and related commits
            repo_name_cnt = {k: v for k, v in repo_name_cnt.items() if v > LargeChangeFilter.Commit_Count_Threshold}
            new_commit_infos = commit_infos
            commit_infos = []
            for commit in new_commit_infos:
                if commit.repo_name in repo_name_cnt.keys():
                    self._info(f'{cve.cve_id} {commit.git_url} find a bunch of commits for {cve.cve_id}')
                elif commit.repo_name in large_change_repo_name:
                    # discard other related commits, if we find a large change commit in this cve for this repo
                    self._info(f'{cve.cve_id} {commit.git_url} find other related commit for {commit.repo_name}')
                else:
                    commit_infos.append(commit)

            result_cve.append(
                update_cve_with_commits(cve, commit_infos)
            )
        return result_cve


class KeepLatestNonVul(GlobalFilter):
    """
        this filter try to keep the latest non-vul functions
    """

    def filter(self, cve_list: list[CveWithCommitInfo]) -> list[CveWithCommitInfo]:
        # record the latest time a file has appeared
        file_latest_mapping: dict[str, dict[str, tuple]] = {}

        for cve in cve_list:

            for commit in cve.commits:
                repo_name = commit.repo_name
                commit_time = commit.commit_date
                commit_hash = commit.commit_hash
                file_latest_mapping.setdefault(repo_name, {})

                for file in commit.files:
                    file_path = file.file_path

                    if (file_path not in file_latest_mapping[repo_name] or
                            file_latest_mapping[repo_name][file_path][0] < commit_time):
                        file_latest_mapping[repo_name][file_path] = (commit_time, commit_hash)
        result_cve = []
        for cve in cve_list:
            commit_infos = []
            for commit in cve.commits:
                repo_name = commit.repo_name
                this_repo_latest_file_commit = file_latest_mapping[repo_name]
                commit_time = commit.commit_date
                commit_hash = commit.commit_hash
                new_files = []

                for file in commit.files:
                    file_path = file.file_path
                    if this_repo_latest_file_commit[file_path][0] != commit_time:
                        # remove this file all non-vul funcs
                        new_files.append(CommitFile(
                            file.file_name, file.file_path, file.language,
                            vulnerable_functions=file.vulnerable_functions, non_vulnerable_functions=[]
                        ))
                    else:
                        new_files.append(file)
                commit_infos.append(
                    update_commit_info_with_files(commit, new_files)
                )
            result_cve.append(
                update_cve_with_commits(cve, commit_infos)
            )
        return result_cve


class RemoveNonVulAppearInVulFilter(GlobalFilter):
    """
        this filter trying to remove non-vul func that were detected as vul func
    """

    def get_func_key(self, vul: VulnerableFunction | NonVulnerableFunction):
        if isinstance(vul, VulnerableFunction):
            return f'{vul.func_name}$$${vul.parameter_list_signature_before}'
        elif isinstance(vul, NonVulnerableFunction):
            return f'{vul.func_name}$$${vul.parameter_list_signature}'

    def filter(self, cve_list: list[CveWithCommitInfo]) -> list[CveWithCommitInfo]:
        vul_func_record: dict[str, dict[str, set[str]]] = {}  # repo -> file -> funcs
        for cve in cve_list:
            for commit in cve.commits:
                repo_name = commit.repo_name
                vul_func_record.setdefault(repo_name, {})
                for file in commit.files:
                    file_path = file.file_path
                    vul_func_record[repo_name].setdefault(file_path, set())
                    for vul_func in file.vulnerable_functions:
                        vul_func_record[repo_name][file_path].add(self.get_func_key(vul_func))

        # let's remove non-vul
        result_cve = []
        for cve in cve_list:
            commit_infos = []
            for commit in cve.commits:
                repo_name = commit.repo_name
                new_files = []
                for file in commit.files:
                    new_non_vul_funcs = []
                    file_path = file.file_path
                    for non_vul_func in file.non_vulnerable_functions:
                        key = self.get_func_key(non_vul_func)
                        if key in vul_func_record[repo_name][file_path]:
                            # remove this non-vul
                            pass
                        else:
                            new_non_vul_funcs.append(non_vul_func)

                    new_files.append(CommitFile(
                        file.file_name, file.file_path, file.language,
                        vulnerable_functions=file.vulnerable_functions, non_vulnerable_functions=new_non_vul_funcs
                    ))

                commit_infos.append(
                    update_commit_info_with_files(commit, new_files)
                )
            result_cve.append(
                update_cve_with_commits(cve, commit_infos)
            )
        return result_cve


class RemoveNonVulDuplicateFilter(GlobalFilter):
    """
        this filter trying remove non-vul func with the same content, keep only one non-vul func copy
    """

    def get_func_key(self, vul: NonVulnerableFunction):
        return f'{vul.func_name}$$${vul.parameter_list_signature}'

    def filter(self, cve_list: list[CveWithCommitInfo]) -> list[CveWithCommitInfo]:
        non_vul_record: dict[str, dict[str, dict[str, set[str]]]] = {}
        result_cve = []
        for cve in cve_list:
            commit_infos = []
            for commit in cve.commits:

                repo_name = commit.repo_name
                non_vul_record.setdefault(repo_name, {})
                new_files = []

                for file in commit.files:
                    file_path = file.file_path
                    non_vul_record[repo_name].setdefault(file_path, {})
                    new_non_vul_funcs = []

                    for non_vul_func in file.non_vulnerable_functions:
                        func_key = self.get_func_key(non_vul_func)
                        content = non_vul_func.func
                        non_vul_record[repo_name][file_path].setdefault(func_key, set())
                        if content in non_vul_record[repo_name][file_path][func_key]:
                            # remove this non-vul
                            pass
                        else:
                            non_vul_record[repo_name][file_path][func_key].add(content)
                            new_non_vul_funcs.append(non_vul_func)

                    new_files.append(
                        update_file_with_funcs(file, file.vulnerable_functions, new_non_vul_funcs)
                    )

                commit_infos.append(
                    update_commit_info_with_files(commit, new_files)
                )
            result_cve.append(
                update_cve_with_commits(cve, commit_infos)
            )
        return result_cve


class DebugGlobalFilter(GlobalFilter):
    """ only for debug """

    def filter(self, cve_list: list[CveWithCommitInfo]) -> list[CveWithCommitInfo]:
        for cve in cve_list:
            global_logger.debug(f'{cve.cve_id} {cve.cwe_ids}')
            for commit in cve.commits:
                global_logger.debug(f'{commit.git_url} {commit}')

        return cve_list


############################################################################################################
#####################################  LOCAL FILTER ########################################################

class TestFunctionFilter(LocalFilter):
    """
        filter some test function
    """

    def my_filter(self, func_name: str) -> bool:
        func_name = func_name.split('::')[-1]  # c++ func name
        test_func_prefix = ["START_TEST", "TEST", "DEF_TEST", "IN_PROC_BROWSER_TEST", "BOOST_AUTO_TEST_CASE",
                            "DROGON_TEST", "test", "assert", ]
        for prefix in test_func_prefix:
            if func_name.startswith(prefix):
                return True

        if func_name.endswith('test'):
            return True

        return False

    def filter_vul(self, vul_func: VulnerableFunction) -> bool:
        return self.my_filter(vul_func.func_name)

    def filter_non_vul(self, non_vul_func: NonVulnerableFunction) -> bool:
        return self.my_filter(non_vul_func.func_name)


class LargeNonVulFunctionFilter(LocalFilter):
    """
        filter large non-vul functions
    """

    Non_Vul_Function_Line_Threshold = 120

    def filter_vul(self, vul_func: VulnerableFunction) -> bool:
        return False

    def filter_non_vul(self, non_vul_func: NonVulnerableFunction) -> bool:
        return len(non_vul_func.func.split('\n')) > LargeNonVulFunctionFilter.Non_Vul_Function_Line_Threshold


class LargeVulFunctionFilter(LocalFilter):
    """
        filter large vul functions, we keep as many vul functions as possible.
    """

    Vul_Function_Line_Threshold = 800

    def filter_vul(self, vul_func: VulnerableFunction) -> bool:
        return len(vul_func.func_after.split('\n')) > LargeVulFunctionFilter.Vul_Function_Line_Threshold

    def filter_non_vul(self, non_vul_func: NonVulnerableFunction) -> bool:
        return False


############################################################################################################

def run_filters(cve_list: list[CveWithCommitInfo], total_filters: list[FilterBase], debug_info = True) -> list[
    CveWithCommitInfo]:
    recorder = FilterProcessRecorder()
    if debug_info:
        recorder.record_and_print(global_logger, cve_list)

    # run all filters
    for cur_filter in total_filters:

        if isinstance(cur_filter, GlobalFilter):
            cve_list = cur_filter.filter(cve_list)
        elif isinstance(cur_filter, LocalFilter):
            cve_list = iterate_all_cve(None, cve_list, cur_filter.filter_vul, cur_filter.filter_non_vul)
            #
            # cve_list = multiprocessing_apply_data_with_logger(
            #     partial(iterate_all_cve,vul_filter= cur_filter.filter_vul, non_vul_filter=cur_filter.filter_non_vul) , cve_list, chunk_mode=True
            # )
        if debug_info:
            recorder.record_and_print(global_logger, cve_list, cur_filter.filter_name)

    return cve_list
