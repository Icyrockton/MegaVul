from dataclasses import dataclass
from pathlib import Path
from typing import Optional

import chardet

from vul4c.util.storage import StorageLocation


@dataclass
class DownloadedCommitInfo:
    repo_name: str
    commit_msg: str
    commit_hash: str
    parent_commit_hash: str
    commit_date: int  # unix timestamp (author commit date)
    diff_file_paths: list[str]
    git_url: str


@dataclass
class VulnerableFunction:
    func_name: str  # consistent before and after
    # before function has vulnerability, while after function is clean
    parameter_list_signature_before: str
    parameter_list_before: list
    return_type_before: str
    func_before: str
    abstract_func_before: str
    abstract_symbol_table_before: dict
    func_graph_path_before: str | None

    parameter_list_signature_after: str
    parameter_list_after: list
    return_type_after: str
    func_after: str
    abstract_func_after: str
    abstract_symbol_table_after: dict
    func_graph_path_after: str | None

    # diff info
    diff_func: str
    diff_line_info: dict  # [deleted_lines, added_lines]


@dataclass
class NonVulnerableFunction:
    func_name: str
    parameter_list_signature: str
    parameter_list: list
    return_type: str
    func: str
    abstract_func: str
    abstract_symbol_table: dict
    func_graph_path: str | None


@dataclass
class CommitFile:
    file_name: str
    file_path: str  # file path in source
    language: str  # this file language [c,cpp]
    vulnerable_functions: list[VulnerableFunction]
    non_vulnerable_functions: list[NonVulnerableFunction]

    def __repr__(self):
        vul_names = ', '.join([func.func_name for func in self.vulnerable_functions])
        if len(self.non_vulnerable_functions) > 5:
            non_vul_names = ', '.join([func.func_name for func in self.non_vulnerable_functions[:5]])
            non_vul_names += f', ...[Total {len(self.non_vulnerable_functions)} Non-Vulnerable Functions]'
        else:
            non_vul_names = ', '.join([func.func_name for func in self.non_vulnerable_functions])
        return f'file_name={self.file_name}, vul_funcs=[{vul_names}], non_vul_funcs=[{non_vul_names}]'


@dataclass
class CommitInfo:
    repo_name: str
    commit_msg: str
    commit_hash: str
    parent_commit_hash: str
    commit_date: int  # unix timestamp (author commit date)
    raw_file_paths: list[str]  # if the number of functions in file is empty, this file will be filtered
    files: list[CommitFile]
    git_url: str

    def __repr__(self):
        return f"{self.repo_name}:{self.commit_hash} {self.git_url}, files={self.files}"


@dataclass
class RawCommitInfo:
    repo_name: str
    commit_msg: str
    commit_hash: str
    parent_commit_hash: str
    commit_date: int  # unix timestamp (author commit date)
    file_paths: list[str]
    tree_url: Optional[str]
    git_url: str


@dataclass
class CveWithCommitInfo:
    cve_id: str
    cwe_ids: list[str]
    description: str
    publish_date: str
    last_modify_date: str
    commits: list[CommitInfo]
    # cvss
    cvss_vector: Optional[str]
    cvss_base_score: Optional[float]
    cvss_base_severity: Optional[str]
    cvss_is_v3: Optional[bool]

    def __repr__(self):
        return f"CveWithCommitInfo(cve_id='{self.cve_id}', cwe_ids={self.cwe_ids}, commits={self.commits}, cvss_vector={self.cvss_vector})"


@dataclass
class CvssMetrics:
    cvss_vector: Optional[str] = None
    cvss_score: Optional[float] = None
    cvss_severity: Optional[str] = None
    cvss_3: Optional[bool] = None


# need dataclass inheritance
@dataclass
class CveWithReferenceUrl:
    cve_id: str
    cwe_ids: list[str]
    description: str
    publish_date: str
    last_modify_date: str
    reference_urls: list[str]
    # cvss
    cvss_vector: Optional[str]
    cvss_base_score: Optional[float]
    cvss_base_severity: Optional[str]
    cvss_is_v3: Optional[bool]


@dataclass
class CveWithDownloadedCommitInfo:
    cve_id: str
    cwe_ids: list[str]
    description: str
    publish_date: str
    last_modify_date: str
    commits: list[DownloadedCommitInfo]
    # cvss
    cvss_vector: Optional[str]
    cvss_base_score: Optional[float]
    cvss_base_severity: Optional[str]
    cvss_is_v3: Optional[bool]


# c/c++ extension
HeaderExtension = ['h']  # maybe cpp file or c file
CFileExtension = ['c']
CppFileExtension = ['cc', 'cpp', 'cxx', 'hpp', 'hxx', 'hh']
AcceptedFileExtension = [*HeaderExtension, *CFileExtension, *CppFileExtension]


def filter_accepted_files(file_paths: list[str]) -> list[str]:
    res = []
    # for large commit (file changes > 50 , we ignore)
    if len(file_paths) > 50:
        return res
    for file_path in file_paths:
        file_name = file_path.split('/')[-1]
        if '.' in file_name:
            if file_name.split('.')[-1] in AcceptedFileExtension:
                res.append(file_path)
    return res


def try_repo_name_merge(repo_name: str) -> str:
    """ memcached/memcached -> memcached  """
    repo_name = repo_name.replace('.git', '')
    if len((split_repo := repo_name.split('/'))) == 2:
        owner, repo = split_repo
        if owner == repo:
            return owner
    return repo_name


def cache_commit_file_dir(repo_name: str, commit_hash: str, current_hash: str) -> Path:
    # avoid commit hash collision
    root_dir = StorageLocation.cache_dir() / 'commit_file_cache'
    dir_path = root_dir / repo_name / commit_hash / current_hash
    return dir_path


def trunc_commit_file_name(file_path: str) -> str:
    return file_path.split('/')[-1]


def try_decode_binary_data_and_write_to_file(data: bytes, save_path: Path):
    save_path.parent.mkdir(parents=True, exist_ok=True)
    with save_path.open(mode='w') as f:
        file_content = try_decode_binary_data(data)
        f.write(file_content)


def try_decode_binary_data(data: bytes) -> str:
    encodings_to_try = ['utf-8', 'ascii']

    for encoding in encodings_to_try:
        try:
            return data.decode(encoding)
        except UnicodeDecodeError:
            pass

    detect_result = chardet.detect(data)
    detected_encoding = detect_result['encoding']

    try:
        return data.decode(detected_encoding)
    except UnicodeDecodeError:
        raise AssertionError(f'decode error {detected_encoding} {data}')
