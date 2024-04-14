import difflib
import logging
from enum import StrEnum
from pathlib import Path
from typing import Iterator, Tuple
from megavul.git_platform.common import CveWithDownloadedCommitInfo, DownloadedCommitInfo, CveWithCommitInfo, \
    try_repo_name_merge, trunc_commit_file_name
import subprocess
from megavul.parser.parser_util import ExtractedFunction
from megavul.util.utils import load_from_marshmallow_dataclass_json_file, check_file_exists_and_not_empty
import tempfile

def get_file_type_using_linguist(fp: Path):
    """
example output:
        extension_install_prompt.h: 476 lines (387 sloc)
        type:      Text
        mime type: text/plain
        language:  C++
    """
    suffix = fp.name.split('.')[-1]
    suffix = f'.{suffix}'
    with tempfile.NamedTemporaryFile('w',suffix=suffix) as tmp_f:
        # create temporary file to allow linguistic to escape .gitignore
        tmp_f.write(fp.open('r').read())
        tmp_f.flush()
        output = subprocess.check_output(f'github-linguist {tmp_f.name}', shell=True, text=True, stderr=subprocess.STDOUT)
        language = output.splitlines()[3].strip()
        language = language.split(':')[1].strip().lower()
        # return value: ['c++', 'c', 'objective-c']
        return language


def traverse_all_commit(cve_with_commit: list[CveWithDownloadedCommitInfo]) -> Iterator[DownloadedCommitInfo]:
    for cve in cve_with_commit:
        for commit in cve.commits:
            yield commit


def traverse_single_commit(commit: DownloadedCommitInfo) -> Iterator[Tuple[str, str, str]]:
    for hash in [commit.commit_hash, commit.parent_commit_hash]:
        for f_path in commit.diff_file_paths:
            yield commit.commit_hash, hash, f_path


class RepoType(StrEnum):
    PureC = 'c' # All the files in this project are C
    PureCpp = 'cpp' # All the files in this project are CPP
    Mix = 'mix' # CPP and C mix
    Java = 'java'
    # extend other languages

def difflib_diff_func(before:str, after:str) -> tuple[str,dict]:
    added_lines ,deleted_lines  = [] ,[]
    raw_diff = []
    for idx,line in enumerate(difflib.unified_diff(
        before.split('\n'), after.split('\n') , 'func_before' , 'func_after' ,lineterm=''
    )):
        raw_diff.append(line)
        if idx < 2:
            continue
        if line[0] == '-':
            deleted_lines.append(line[1:])
        elif line[0] == '+':
            added_lines.append(line[1:])
    parse_diff_dict =  { 'deleted_lines':deleted_lines , 'added_lines' : added_lines }
    raw_diff = '\n'.join(raw_diff)
    return raw_diff,parse_diff_dict



class ExtractCommitDiffRecorder:

    def __init__(self,parsed_commit_cache_dir:Path):
        self.__raw_func_cnt = 0  # before diff function counter
        self.__raw_file_cnt = 0
        self.__raw_commit_cnt = 0
        self.__raw_cve_cnt = 0

        self.__diff_vul_func_cnt = 0
        self.__diff_no_vul_func_cnt = 0
        self.__diff_file_cnt = 0
        self.__diff_commit_cnt = 0
        self.__diff_cve_cnt = 0
        self.parsed_commit_cache_dir = parsed_commit_cache_dir

    def record_raw_info(self, cve_with_commit: list[CveWithDownloadedCommitInfo]):
        self.__raw_cve_cnt = len(cve_with_commit)
        for cve in cve_with_commit:
            self.__raw_commit_cnt += len(cve.commits)
            for commit in cve.commits:
                self.__raw_file_cnt += len(commit.diff_file_paths)
                new_repo_name = try_repo_name_merge(commit.repo_name)
                for f_path in commit.diff_file_paths:
                    f_name = trunc_commit_file_name(f_path)
                    this_file_path = (self.parsed_commit_cache_dir /
                                      new_repo_name / commit.commit_hash / commit.commit_hash / f_name)
                    if not check_file_exists_and_not_empty(this_file_path) :
                        continue
                    this_file_funcs = load_from_marshmallow_dataclass_json_file(ExtractedFunction, this_file_path,
                                                                                    is_list=True)
                    self.__raw_func_cnt += len(this_file_funcs)

    def record_and_print_raw_info(self,logger: logging.Logger,cve_with_commit: list[CveWithDownloadedCommitInfo]):
        self.record_raw_info(cve_with_commit)
        self.print_raw_info(logger)

    def print_raw_info(self, logger: logging.Logger):
        logger.info(
            f'[CommitDiff Recorder] Raw info before parse, CVE:{self.__raw_cve_cnt} Commits:{self.__raw_commit_cnt} Files:{self.__raw_file_cnt} Functions:{self.__raw_func_cnt}')

    def record_diff_info(self, cve_with_parsed_commit: list[CveWithCommitInfo]):
        self.__diff_cve_cnt = len(cve_with_parsed_commit)
        for cve in cve_with_parsed_commit:
            self.__diff_commit_cnt += len(cve.commits)
            for commit in cve.commits:
                self.__diff_file_cnt += len(commit.files)
                for file in commit.files:
                    self.__diff_vul_func_cnt += len(file.vulnerable_functions)
                    self.__diff_no_vul_func_cnt += len(file.non_vulnerable_functions)

    def print_diff_info(self, logger: logging.Logger):
        logger.info(
            f'[CommitDiff Recorder] After finding commits that parsed successfully, CVE:{self.__diff_cve_cnt} Commits:{self.__diff_commit_cnt} Files:{self.__diff_file_cnt} Vul-Functions:{self.__diff_vul_func_cnt} Non-Vul-Functions:{self.__diff_no_vul_func_cnt}')

    def record_and_print_diff_info(self,logger: logging.Logger,cve_with_parsed_commit: list[CveWithCommitInfo]):
        self.record_diff_info(cve_with_parsed_commit)
        self.print_diff_info(logger)

if __name__ == '__main__':
    print(difflib_diff_func(
        """    if (track->mode == MODE_MOV) {
            if (track->timescale > UINT16_MAX) {
                if (mov_get_lpcm_flags(track->par->codec_id))
                    tag = AV_RL32("lpcm");
                version = 2;
            """,
        """    if (track->mode == MODE_MOV) {
            if (track->timescale > UINT16_MAX || !track->par->channels) {
                if (mov_get_lpcm_flags(track->par->codec_id))
                    tag = AV_RL32("lpcm");
                version = 2;
            """
    )[1])