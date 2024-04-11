from typing import Optional
from megavul.git_platform.common import CveWithCommitInfo, CommitInfo, VulnerableFunction, NonVulnerableFunction
from megavul.pipeline.json_save_location import cve_with_graph_abstract_commit_json_path, megavul_json_path, \
    megavul_simple_json_path
from megavul.util.utils import load_from_marshmallow_dataclass_json_file, save_marshmallow_dataclass_to_json_file
from dataclasses import dataclass


@dataclass
class MegaVulFunction:
    cve_id: str
    cwe_ids: list[str]
    cvss_vector: Optional[str]
    cvss_base_score: Optional[float]
    cvss_base_severity: Optional[str]
    cvss_is_v3: Optional[bool]
    publish_date: str

    repo_name: str
    commit_msg: str
    commit_hash: str
    parent_commit_hash: str
    commit_date: int
    git_url: str

    file_path: str
    func_name: str
    # when `is_vul = 1` xxxxx_before will exist, indicating a vulnerable function.
    parameter_list_signature_before: Optional[str]
    parameter_list_before: Optional[list]
    return_type_before: Optional[str]
    func_before: Optional[str]
    abstract_func_before: Optional[str]
    abstract_symbol_table_before: Optional[dict]
    func_graph_path_before: Optional[str | None]

    parameter_list_signature: str
    parameter_list: list
    return_type: str
    func: str
    abstract_func: str
    abstract_symbol_table: dict
    func_graph_path: str | None

    # diff info
    diff_func: Optional[str]
    diff_line_info: Optional[dict]  # [deleted_lines, added_lines]

    is_vul: bool

@dataclass
class MegaVulSimpleFunction:
    cve_id: str
    cwe_ids: list[str]
    cvss_vector: Optional[str]
    cvss_is_v3: Optional[bool]

    repo_name: str
    commit_msg: str
    commit_hash: str
    git_url: str
    file_path: str
    func_name: str

    # when `is_vul = 1` xxxxx_before will exist, indicating a vulnerable function.
    func_before: Optional[str]
    abstract_func_before: Optional[str]
    func_graph_path_before: Optional[str | None]

    func: str
    abstract_func: str
    func_graph_path: str | None

    # diff info
    diff_func: Optional[str]
    diff_line_info: Optional[dict]  # [deleted_lines, added_lines]

    is_vul: bool

def add_vul_func(dst: list[MegaVulFunction],simple_dst:list[MegaVulSimpleFunction], cve: CveWithCommitInfo, commit: CommitInfo, file_path: str,
                 vul_func: VulnerableFunction):
    dst.append(MegaVulFunction(
        cve.cve_id, cve.cwe_ids, cve.cvss_vector, cve.cvss_base_score, cve.cvss_base_severity, cve.cvss_is_v3,
        cve.publish_date,
        commit.repo_name, commit.commit_msg, commit.commit_hash, commit.parent_commit_hash, commit.commit_date,
        commit.git_url,
        file_path,
        vul_func.func_name, vul_func.parameter_list_signature_before, vul_func.parameter_list_before,
        vul_func.return_type_before, vul_func.func_before, vul_func.abstract_func_before,
        vul_func.abstract_symbol_table_before, vul_func.func_graph_path_before,
        vul_func.parameter_list_signature_after, vul_func.parameter_list_after, vul_func.return_type_after,
        vul_func.func_after, vul_func.abstract_func_after, vul_func.abstract_symbol_table_after,
        vul_func.func_graph_path_after, vul_func.diff_func, vul_func.diff_line_info, True
    ))

    simple_dst.append( MegaVulSimpleFunction(
        cve.cve_id, cve.cwe_ids, cve.cvss_vector, cve.cvss_is_v3,
        commit.repo_name, commit.commit_msg, commit.commit_hash, commit.git_url,file_path,
        vul_func.func_name, vul_func.func_before, vul_func.abstract_func_before, vul_func.func_graph_path_before,
        vul_func.func_after, vul_func.abstract_func_after, vul_func.func_graph_path_after, vul_func.diff_func, vul_func.diff_line_info, True
    )
    )


def add_non_vul_func(dst: list,simple_dst:list[MegaVulSimpleFunction], cve: CveWithCommitInfo, commit: CommitInfo, file_path: str,
                     non_vul_func: NonVulnerableFunction):
    dst.append(MegaVulFunction(
        cve.cve_id, cve.cwe_ids, cve.cvss_vector, cve.cvss_base_score, cve.cvss_base_severity, cve.cvss_is_v3,
        cve.publish_date,
        commit.repo_name, commit.commit_msg, commit.commit_hash, commit.parent_commit_hash, commit.commit_date,
        commit.git_url,
        file_path,
        non_vul_func.func_name,None,None,None,None,None,None,None,
        non_vul_func.parameter_list_signature,non_vul_func.parameter_list,non_vul_func.return_type,
        non_vul_func.func,non_vul_func.abstract_func,non_vul_func.abstract_symbol_table,non_vul_func.func_graph_path,
        None,None,False
    ))

    simple_dst.append( MegaVulSimpleFunction(
        cve.cve_id, cve.cwe_ids, cve.cvss_vector,  cve.cvss_is_v3,
        commit.repo_name, commit.commit_msg, commit.commit_hash,commit.git_url, file_path,
        non_vul_func.func_name, None, None, None, non_vul_func.func, non_vul_func.abstract_func, non_vul_func.func_graph_path,
        None, None, False
    ))


def generate_megavul():
    """
        generate a flattened version of MegaVul for ease of use, and distribute this version dataset
    """
    cve_with_graph_abstract_commit: list[CveWithCommitInfo] = load_from_marshmallow_dataclass_json_file(
        CveWithCommitInfo,
        cve_with_graph_abstract_commit_json_path, True)

    final_result :list[MegaVulFunction] = []
    simple_final_result :list[MegaVulSimpleFunction] = []

    for cve in cve_with_graph_abstract_commit:
        for commit in cve.commits:
            for file in commit.files:
                file_path = file.file_path
                for f in file.vulnerable_functions:
                    add_vul_func(final_result,simple_final_result, cve, commit,file_path,f)
                for f in file.non_vulnerable_functions:
                    add_non_vul_func(final_result,simple_final_result ,cve, commit,file_path,f)

    save_marshmallow_dataclass_to_json_file(MegaVulFunction, megavul_json_path, final_result)
    save_marshmallow_dataclass_to_json_file(MegaVulSimpleFunction, megavul_simple_json_path, final_result)

if __name__ == '__main__':
    generate_megavul()
