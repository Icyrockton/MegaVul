import json
from pathlib import Path
graph_dir = Path('../megavul/storage/result/graph')

with Path("../megavul/storage/result/megavul_simple.json").open(mode='r') as f:
    megavul = json.load(f)
    item = megavul[9]
    cve_id = item['cve_id'] # CVE-2022-24786
    cvss_vector = item['cvss_vector']   # AV:N/AC:L/Au:N/C:P/I:P/A:P
    is_vul = item['is_vul'] # True
    if is_vul:
        func_before = item['func_before']  # vulnerable function

    func_after = item['func']   # after vul function fixed(i.e., clean function)
    abstract_func_after = item['abstract_func']

    diff_line_info = item['diff_line_info'] # {'deleted_lines': ['pjmedia_rtcp_comm .... ] , 'added_lines': [ .... ] }
    git_url = item['git_url']   # https://github.com/pjsip/pjproject/commit/11559e49e65bdf00922ad5ae28913ec6a198d508

    if item['func_graph_path_before'] is not None: # graphs of some functions cannot be exported successfully
        graph_file_path = graph_dir / item['func_graph_path_before']
        graph_file = json.load(graph_file_path.open(mode='r'))
        nodes, edges = graph_file['nodes'] , graph_file['edges']
        print(nodes)    # [{'version': '0.1', 'language': 'NEWC', '_label': 'META_DATA', 'overlays': ....
        print(edges)    # [{'innode': 196, 'outnode': 2, 'etype': 'AST', 'variable': None}, ...]
