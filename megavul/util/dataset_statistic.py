from megavul.git_platform.common import CveWithCommitInfo
from megavul.pipeline.json_save_location import cve_with_graph_abstract_commit_json_path
from megavul.util.utils import load_from_marshmallow_dataclass_json_file
from megavul.util.config import crawling_language

if __name__ == '__main__':
    cve_with_graph_abstract_commit: list[CveWithCommitInfo] = load_from_marshmallow_dataclass_json_file(
        CveWithCommitInfo,
        cve_with_graph_abstract_commit_json_path, True)

    commit_cnt = 0
    cve_cnt = len(cve_with_graph_abstract_commit)
    cwe_set = set()
    repo_set = set()
    vul_cnt = 0
    non_vul_cnt = 0

    for cve in cve_with_graph_abstract_commit:
        cwe_set.update(cve.cwe_ids)
        for commit in cve.commits:
            commit_cnt+=1
            repo_set.add(commit.repo_name)
            for file in commit.files:
                vul_cnt += len(file.vulnerable_functions)
                non_vul_cnt += len(file.non_vulnerable_functions)

    print(f"MegaVul for {crawling_language}")
    print(f"Number of Repositories = {len(repo_set)}")
    print(f"Number of CVE IDs = {cve_cnt}")
    print(f"Number of CWE IDs = {len(cwe_set)}")
    print(f"Number of Commits = {commit_cnt}")
    print(f"Number of Vul/Non-Vul Function = {vul_cnt}/{non_vul_cnt}")

