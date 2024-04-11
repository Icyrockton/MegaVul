from megavul.util.storage import StorageLocation

result_dir = StorageLocation.result_dir()

all_cve_from_nvd_json_path = result_dir / 'all_cve_from_nvd.json'
cve_with_reference_url_json_path = result_dir / "cve_with_reference_url.json"
cve_with_downloaded_commit_json_path = result_dir / "cve_with_downloaded_commit.json"
cve_with_parsed_commit_json_path = result_dir / 'cve_with_parsed_commit.json'
cve_with_parsed_and_filtered_commit_json_path = result_dir / 'cve_with_parsed_filtered_commit.json'
cve_with_graph_abstract_commit_json_path = result_dir / 'cve_with_graph_abstract_commit.json'
megavul_json_path = result_dir / 'megavul.json'
megavul_simple_json_path = result_dir / 'megavul_simple.json'