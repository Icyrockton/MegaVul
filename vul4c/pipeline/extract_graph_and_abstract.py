import glob
import json
import logging
import os
import subprocess
import signal
from time import sleep
from vul4c.parser.clike_code_abstracter import CLikeCodeAbstracter
from vul4c.pipeline.json_save_location import cve_with_parsed_and_filtered_commit_json_path, \
    cve_with_graph_abstract_commit_json_path
from vul4c.util.logging_util import global_logger
from vul4c.util.storage import StorageLocation
from vul4c.git_platform.common import VulnerableFunction, NonVulnerableFunction, CveWithCommitInfo
from vul4c.util.utils import load_from_marshmallow_dataclass_json_file, save_str, proxies, convert_to_jvm_proxy, \
    save_data_as_json, read_json_from_local, save_marshmallow_dataclass_to_json_file, compress_directory_to_zip
import shutil
from pathlib import Path
from vul4c.util.concurrent_util import multiprocessing_apply_data_with_logger, multiprocessing_map

generate_source_dir = StorageLocation.cache_dir() / "joern_file_cache"
graph_save_dir = StorageLocation.result_dir() / "graph"

def generate_source_file(cve_with_commit: list[CveWithCommitInfo], using_cache: bool = False):
    save_dir = generate_source_dir
    save_index_file = save_dir / "Vul4C_index.json"
    if save_dir.exists() and not using_cache:
        global_logger.info(f'{save_dir} already exists, removing this directory...')
        shutil.rmtree(save_dir)
    elif save_dir.exists() and save_index_file.exists() and using_cache:
        global_logger.info(f'{save_dir} already exists, using cache')
        return

    index_set = []
    for cve in cve_with_commit:
        for commit in cve.commits:
            repo_name = commit.repo_name
            commit_hash = commit.commit_hash
            this_commit_dir = save_dir / repo_name / commit_hash
            index_set.append(str(this_commit_dir))

            for file in commit.files:
                this_file_dir = this_commit_dir / file.file_name
                file_language = file.language

                vul_func: VulnerableFunction
                for idx, vul_func in enumerate(file.vulnerable_functions):
                    idx = str(idx)
                    func_dir = this_file_dir / "vul"
                    save_str(vul_func.func_before, func_dir / "before" / idx / f"{idx}.{file_language}")
                    save_str(vul_func.func_after, func_dir / "after" / idx / f"{idx}.{file_language}")

                non_vul_func: NonVulnerableFunction
                for idx, non_vul_func in enumerate(file.non_vulnerable_functions):
                    idx = str(idx)
                    func_dir = this_file_dir / "non_vul"
                    save_str(non_vul_func.func, func_dir / idx / f"{idx}.{file_language}")

    save_data_as_json(index_set, save_index_file)


def run_joern_once(timeout) -> int:
    """
        running joern test script to extract functions is prone to OutOfMemoryError(OOM) exceptions. :)
        we kill it and re-run until all function graphs are extracted.
    """
    working_dir = StorageLocation.joern_dir()
    proxy_str = ''
    if proxies is not None:
        proxy_str = convert_to_jvm_proxy(proxies)
        global_logger.info(f'running joern with proxy : {proxy_str}')
    try:
        my_env = os.environ.copy()
        my_env['Vul4CInputDir'] = str(generate_source_dir)
        p = subprocess.Popen(
            f'sbt {proxy_str} "testOnly io.joern.c2cpg.io.Vul4CGraphGenerateTest -- -t "generateGraph""',
            shell=True, start_new_session=True, cwd=working_dir, env=my_env, stderr=subprocess.STDOUT)
        return_code = p.wait(timeout=timeout)
        if return_code != 0:
            global_logger.error('running joern failed. please see the error message')
            return -1
        return 1
    except subprocess.TimeoutExpired:
        global_logger.info(f'joern run time out, terminating the process group...')
        os.killpg(os.getpgid(p.pid), signal.SIGKILL)
        sleep(5)
        return 0

def run_joern():
    run_joern_cnt = 0
    global_logger.info('[Joern] begin run joern!')
    while True:
        return_code = run_joern_once(70)
        if return_code > 0:
            global_logger.info('[Joern] joern completely!')
            break
        elif return_code == 0:
            run_joern_cnt += 1
            global_logger.info(f'[Joern] run joern {run_joern_cnt} times')
            continue
        else:
            global_logger.info(f'[Joern] run error happened')
            break

def check_json_complete(path:Path):
    try:
        read_json_from_local(path)
    except json.decoder.JSONDecodeError:
        global_logger.info(f'json {path} is corrupted, remove this file')
        os.remove(path)

def call_joern_to_generate_graph():
    joern_path = StorageLocation.joern_dir()
    joern_script_path = StorageLocation.joern_script_path()
    joern_script_name = joern_script_path.name

    if not joern_path.exists():
        global_logger.error(f'missing joern source code in {joern_path}, please git clone joern first.')
        return
    if not joern_script_path.exists():
        global_logger.error(f'missing generate graph script file in {joern_script_path}.')
        return

    # copy Test script, we will run this TestFile later
    shutil.copy(joern_script_path,
                joern_path / "joern-cli/frontends/c2cpg/src/test/scala/io/joern/c2cpg/io" / joern_script_name)

    run_joern()

    # shutdown is not graceful, some json corrupted, check json is complete
    global_logger.info(f'checking all joern generated json files')
    multiprocessing_map(check_json_complete,generate_source_dir.rglob("*.json"))

    # run joern again
    run_joern()

def find_label_in_nodes(nodes: list[dict], label: str) -> list:
    res = []
    for n in nodes:
        if n['_label'] == label:
            res.append(n)
    return res


def find_method_in_nodes(nodes: list[dict], method_name=None):
    methods = find_label_in_nodes(nodes, 'METHOD')
    if method_name is None:
        return methods
    new_method = []
    for m in methods:
        if m['name'] == method_name:
            new_method.append(m)
    return new_method


def get_node_in_out_map(edges: list[dict]):
    in_nodes, out_nodes = {}, {}  #
    for e in edges:
        # in node ----> out node
        in_node = e['inNode']
        out_node = e['outNode']

        out_nodes.setdefault(in_node, [])
        in_nodes.setdefault(out_node, [])
        if out_node not in out_nodes[in_node]:
            # maybe duplicate , because different types of edge
            out_nodes[in_node].append(out_node)
        if in_node not in in_nodes[out_node]:
            in_nodes[out_node].append(in_node)
    return in_nodes, out_nodes


def check_func_graph_complete(logger: logging.Logger, graph_path: Path, ) -> bool:
    if not graph_path.exists():
        logger.debug(f'{graph_path} graph not found')
        return False

    node_edge_json: dict = read_json_from_local(graph_path)
    node_json = node_edge_json['nodes']
    edge_json = node_edge_json['edges']
    in_nodes, out_nodes = get_node_in_out_map(edge_json)
    method_nodes = find_method_in_nodes(node_json, '<global>')  # <global> METHOD
    parse_error_methods = []
    for m in method_nodes:
        # find method block
        m_id = m['id']
        block_nodes = []
        for block_node in in_nodes[m_id]:
            block_node = node_json[block_node - 1]  # get the node
            if block_node['_label'] == 'BLOCK':  # really block node
                block_nodes.append(block_node)
        # assert len(block_nodes) == 1 , print(block_nodes,path)
        block_node = block_nodes[0]
        # find block node next node
        # if next node is UNKNOWN node, we think the function parse errors
        # print('*'*10)
        unknown_found = False
        for next_node in in_nodes[block_node['id']]:
            next_node = node_json[next_node - 1]
            if next_node['_label'] == 'UNKNOWN':
                unknown_found = True

        if unknown_found:
            parse_error_methods.append(m)

    if len(parse_error_methods) > 0:
        logger.debug(f'find function graph error in {graph_path}')
        return False

    return True


def find_successfully_extracted_func_graph(logger: logging.Logger, cve: CveWithCommitInfo):
    save_dir = generate_source_dir

    for commit in cve.commits:
        repo_name = commit.repo_name
        commit_hash = commit.commit_hash
        this_commit_dir = save_dir / repo_name / commit_hash

        for file in commit.files:
            this_file_dir = this_commit_dir / file.file_name
            this_file_graph_save_dir = graph_save_dir / repo_name / commit_hash / file.file_name
            file_language = file.language

            vul_func: VulnerableFunction
            for idx, vul_func in enumerate(file.vulnerable_functions):
                idx = str(idx)
                func_dir = this_file_dir / "vul"
                before_graph_path = func_dir / "before" / idx / f"{idx}.json"
                after_graph_path = func_dir / "after" / idx / f"{idx}.json"

                before_complete = check_func_graph_complete(logger, before_graph_path)
                after_complete = check_func_graph_complete(logger, after_graph_path)
                if before_complete and after_complete:
                    # all correct
                    final_before_graph_path = this_file_graph_save_dir / "vul" / "before" / f"{idx}.json"
                    final_before_graph_path.parent.mkdir(parents=True, exist_ok=True)
                    final_after_graph_path = this_file_graph_save_dir / "vul" / "after" / f"{idx}.json"
                    final_after_graph_path.parent.mkdir(parents=True, exist_ok=True)
                    if not final_before_graph_path.exists():
                        shutil.copy(before_graph_path, final_before_graph_path)
                    if not final_after_graph_path.exists():
                        shutil.copy(after_graph_path, final_after_graph_path)
                    # populate field
                    vul_func.func_graph_path_before = str(final_before_graph_path.relative_to(graph_save_dir))
                    vul_func.func_graph_path_after = str(final_after_graph_path.relative_to(graph_save_dir))

            non_vul_func: NonVulnerableFunction
            for idx, non_vul_func in enumerate(file.non_vulnerable_functions):
                idx = str(idx)
                func_dir = this_file_dir / "non_vul"
                graph_path = func_dir / idx / f"{idx}.json"

                if check_func_graph_complete(logger, graph_path):
                    final_graph_path = this_file_graph_save_dir / "non_vul" / f"{idx}.json"
                    final_graph_path.parent.mkdir(parents=True, exist_ok=True)
                    if not final_graph_path.exists():
                        shutil.copy(graph_path, final_graph_path)

                    non_vul_func.func_graph_path = str(final_graph_path.relative_to(graph_save_dir))

    return cve


def abstracting_functions(logger: logging.Logger, cve: CveWithCommitInfo):
    code_abstracter = CLikeCodeAbstracter(logger)
    for commit in cve.commits:
        for file in commit.files:
            language = file.language
            vul_func: VulnerableFunction
            for idx, vul_func in enumerate(file.vulnerable_functions):
                abstract_func_before, symbol_table_before = code_abstracter.abstract_code(vul_func.func_before,
                                                                                          language)
                abstract_func_after, symbol_table_after = code_abstracter.abstract_code(vul_func.func_after, language)

                vul_func.abstract_func_before = abstract_func_before
                vul_func.abstract_func_after = abstract_func_after
                vul_func.abstract_symbol_table_before = symbol_table_before
                vul_func.abstract_symbol_table_after = symbol_table_after

            non_vul_func: NonVulnerableFunction
            for idx, non_vul_func in enumerate(file.non_vulnerable_functions):
                abstract_func, symbol_table = code_abstracter.abstract_code(non_vul_func.func, language)
                non_vul_func.abstract_func = abstract_func
                non_vul_func.abstract_symbol_table = symbol_table
    return cve


def info_recorder(cve_list: list[CveWithCommitInfo]):
    total_vul = 0
    parse_succeed_vul = 0
    total_non_vul = 0
    parse_succeed_non_vul = 0

    for cve in cve_list:
        for commit in cve.commits:
            for file in commit.files:
                total_vul += len(file.vulnerable_functions)
                total_non_vul += len(file.non_vulnerable_functions)

                parse_succeed_vul += sum([f.func_graph_path_before is not None for f in file.vulnerable_functions])
                parse_succeed_non_vul += sum([f.func_graph_path is not None for f in file.non_vulnerable_functions])

    global_logger.info(f"Find successfully parsed "
                       f"vulnerable:{parse_succeed_vul}/{total_vul}[{parse_succeed_vul / total_vul * 100.0:.2f}%] "
                       f"non_vulnerable:{parse_succeed_non_vul}/{total_non_vul}[{parse_succeed_non_vul / total_non_vul * 100.0:.2f}%]")


def extract_graph_and_abstract():
    """
    using `Joern` to extract graph
    populate generated file path into the graph path field of VulnerableFunction | NonVulnerableFunction
    (i.e., func_graph_path_before, func_graph_path_after, func_graph_path)
    """

    cve_with_commit = load_from_marshmallow_dataclass_json_file(CveWithCommitInfo,
                                                                cve_with_parsed_and_filtered_commit_json_path, True)

    # step.1 generate c/cpp source file in cache directory
    generate_source_file(cve_with_commit, True)

    # step.2 run joern to extract graph
    call_joern_to_generate_graph()

    # step.3 find the functions whose graphs were successfully extracted
    cve_with_graph_commit = multiprocessing_apply_data_with_logger(
        find_successfully_extracted_func_graph, cve_with_commit, chunk_mode=False
    )

    info_recorder(cve_with_graph_commit)

    # step.4 abstracting function
    cve_with_graph_abstract_commit = multiprocessing_apply_data_with_logger(
        abstracting_functions, cve_with_graph_commit, chunk_mode=False
    )

    # save results
    save_marshmallow_dataclass_to_json_file(CveWithCommitInfo, cve_with_graph_abstract_commit_json_path,
                                            cve_with_graph_abstract_commit)

    global_logger.info('compressing graph directory into zip file......')
    compress_directory_to_zip(graph_save_dir, StorageLocation.result_dir() / "vul4c_graph.zip")


if __name__ == '__main__':
    extract_graph_and_abstract()
