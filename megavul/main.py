from megavul.pipeline.download_cve_from_nvd import crawl_nvd
from megavul.pipeline.extract_and_download_commit import extract_and_download_commit
from megavul.pipeline.extract_commit_diff import extract_commit_diff
from megavul.pipeline.extract_cve_info import extract_cve_info
from megavul.pipeline.extract_graph_and_abstract import extract_graph_and_abstract
from megavul.pipeline.flatten_megavul import generate_megavul

if __name__ == '__main__':

    # step.1 crawl all CVEs from NVD
    crawl_nvd()

    # step.2 find potential commits from reference URLs in each CVE
    extract_cve_info()

    # step.3 download commit from different GIT platforms
    extract_and_download_commit()

    # step.4 using tree-sitter to extract functions and clean dataset using multiple filters
    extract_commit_diff()

    # step.5 using joern to generate graph and generate abstract functions using CodeAbstracter
    extract_graph_and_abstract()

    # step.6 generate the final dataset
    generate_megavul()
