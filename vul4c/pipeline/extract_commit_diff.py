from dataclasses import asdict
import logging
from pathlib import Path
from vul4c.git_platform.common import DownloadedCommitInfo, CveWithDownloadedCommitInfo, try_repo_name_merge, \
    trunc_commit_file_name, \
    CppFileExtension, CFileExtension, HeaderExtension, VulnerableFunction, NonVulnerableFunction, CommitFile, \
    CommitInfo, CveWithCommitInfo
from vul4c.parser.parser_base import ParserBase
from vul4c.parser.parser_util import ExtractedFunction
from vul4c.pipeline.extract_commit_diff_filter import run_filters, TestFunctionFilter, TestFileFilter, MultiCveCommitFilter, \
    DebugGlobalFilter, OneCveMultipleCommitsNonVulDuplicateFilter, OneCveMultipleCommitsByContentDuplicateFilter, \
     LargeChangeFilter, LargeNonVulFunctionFilter, LargeVulFunctionFilter, KeepLatestNonVul, \
    RemoveNonVulAppearInVulFilter, RemoveNonVulDuplicateFilter
from vul4c.pipeline.extract_commit_diff_statistic import MetricsGlobalFilter
from vul4c.pipeline.extract_commit_diff_util import traverse_all_commit, RepoType, traverse_single_commit, \
    get_file_type_using_linguist, ExtractCommitDiffRecorder, difflib_diff_func
from vul4c.pipeline.json_save_location import cve_with_parsed_commit_json_path, cve_with_downloaded_commit_json_path, \
    cve_with_parsed_and_filtered_commit_json_path
from vul4c.util.logging_util import global_logger
from vul4c.util.utils import load_from_marshmallow_dataclass_json_file, check_file_exists_and_not_empty, \
    save_marshmallow_dataclass_to_json_file
from vul4c.util.concurrent_util import multiprocessing_apply_data_with_logger
from vul4c.util.storage import StorageLocation
from functools import partial
from vul4c.parser.parser_c import ParserC
from vul4c.parser.parser_cpp import ParserCpp

parsed_commit_cache_dir = StorageLocation.cache_dir() / "commit_file_parsed_cache"
commit_file_cache_dir = StorageLocation.cache_dir() / "commit_file_cache"

def repo_name_merge(repo_name:str) -> str:
    repo_name = try_repo_name_merge(repo_name)
    special_repo_mapping = {
        'kernel/git/torvalds/linux' : 'torvalds/linux',
        'kernel/git/stable/linux' : 'torvalds/linux',
        'kernel/git/next/linux-next' : 'torvalds/linux',
        'FFmpeg' : 'ffmpeg'
    }
    if repo_name in special_repo_mapping:
        repo_name = special_repo_mapping[repo_name]

    return repo_name


def determine_all_repo_types(cve_with_commit: list[CveWithDownloadedCommitInfo]) -> dict[str, RepoType]:
    repo_type_mapping: dict[str, RepoType] = {}

    for commit in traverse_all_commit(cve_with_commit):
        has_cpp_file, has_c_file = False, False
        repo_name = repo_name_merge(commit.repo_name)

        for f_path in commit.diff_file_paths:
            f_ext = f_path.split('.')[-1].lower()
            if f_ext in ['c']:
                has_c_file = True
            elif f_ext in ['cpp', 'cc', 'hh', 'hxx', 'cxx', 'hpp']:
                has_cpp_file = True

        repo_type = 'mix'
        if has_cpp_file and not has_c_file:
            repo_type = 'cpp'
        elif not has_cpp_file and has_c_file:
            repo_type = 'c'

        if repo_name in repo_type_mapping:
            prev_repo_type = repo_type_mapping[repo_name]
            if prev_repo_type != repo_type:
                repo_type_mapping[repo_name] = RepoType.Mix
        else:
            repo_type_mapping[repo_name] = RepoType(repo_type)

    return repo_type_mapping


def get_file_type(repo_type: RepoType, f_name: str, fp: Path) -> str:
    f_ext = f_name.split('.')[-1]

    if (f_ext in CFileExtension) or (f_ext in HeaderExtension and repo_type == RepoType.PureC):
        return 'c'
    elif (f_ext in CppFileExtension) or (f_ext in HeaderExtension and repo_type == RepoType.PureCpp):
        return 'cpp'
    elif f_ext in HeaderExtension:
        # mix c and cpp, using linguist to detect language
        detect_language = get_file_type_using_linguist(fp)
        if detect_language == 'c':
            return 'c'
        elif detect_language == 'c++':  # cpp
            return 'cpp'

        # object-c header files also have the .h suffix.
        return detect_language # 'objective-c'

    raise RuntimeError(f"unknown file type for {fp}")

def parse_all_commit_files(logger: logging.Logger, cve_with_commit: list[CveWithDownloadedCommitInfo],
                           all_repo_type_mapping: dict[str, RepoType]) -> None:
    parser_list : list[ParserBase] = [
        ParserC(logger),
        ParserCpp(logger)
    ]

    for commit in traverse_all_commit(cve_with_commit):
        repo_type = all_repo_type_mapping[repo_name_merge(commit.repo_name)]

        new_repo_name = repo_name_merge(commit.repo_name)  # merge repo name

        for base_hash, hash, f_path in traverse_single_commit(commit):

            f_name = trunc_commit_file_name(f_path)
            raw_file = commit_file_cache_dir / commit.repo_name / base_hash / hash / f_name

            # save destination
            parsed_file_save_dst = parsed_commit_cache_dir / new_repo_name / base_hash / hash / f_name
            parsed_file_save_dst.parent.mkdir(exist_ok=True, parents=True)

            file_type = get_file_type(repo_type,f_name,raw_file)

            # run parser to parse file and extract functions
            for parser in parser_list:
                if parser.can_handle_this_language(file_type):
                    parser.parse_file(raw_file, parsed_file_save_dst)

def check_commit_all_file_parsed_successfully(logger: logging.Logger, commit: DownloadedCommitInfo) -> bool:
    new_repo_name = repo_name_merge(commit.repo_name)
    this_commit_dir = parsed_commit_cache_dir / new_repo_name / commit.commit_hash / commit.commit_hash
    parent_commit_dir = parsed_commit_cache_dir / new_repo_name / commit.commit_hash / commit.parent_commit_hash

    for f_path in commit.diff_file_paths:
        f_name = trunc_commit_file_name(f_path)
        if not check_file_exists_and_not_empty(this_commit_dir / f_name):
            logger.info(f'{commit.repo_name}:{commit.commit_hash} {f_name} not successfully parsed,'
                        f'please check {commit_file_cache_dir / commit.repo_name / commit.commit_hash / commit.commit_hash / f_name}')
            return False

        if not check_file_exists_and_not_empty(parent_commit_dir / f_name):
            logger.info(f'{commit.repo_name}:{commit.parent_commit_hash} {f_name} not successfully parsed,'
                        f'please check {commit_file_cache_dir / commit.repo_name / commit.commit_hash / commit.parent_commit_hash / f_name}')
            return False

    return True

def get_file_functions_name_mapping(funcs: list[ExtractedFunction]) -> dict[str,ExtractedFunction] :
    # it's hard to track C++ overload function change if only the function signature changed.
    # so we only track C and C++(function signature no changed) change case.
    name_mapping : dict[str,ExtractedFunction | int] = { }

    for f in funcs:
        simple_key = f.func_name
        full_key = f'{f.func_name}$$${f.parameter_list_signature}'

        if simple_key not in name_mapping:
            # for the first occurrence, we only use the `simple_key` as the key
            name_mapping[simple_key] = f
        else:
            # a function with the same name has already appeared before, we should update
            if name_mapping[simple_key] != -1:
                prev_func = name_mapping[simple_key]
                name_mapping[simple_key] = -1
                name_mapping[f'{prev_func.func_name}$$${prev_func.parameter_list_signature}'] = prev_func
            # functions with the same name has already appeared before, we use `full_key` as key
            name_mapping[full_key] = f

    new_name_mapping = { }
    # remove if `value` equal -1
    for k,v in name_mapping.items():
        if v == -1:
            continue
        new_name_mapping[k] = v
    return new_name_mapping



def find_successfully_parsed_commit(logger: logging.Logger, cve_with_commit: list[CveWithDownloadedCommitInfo],
                                    all_repo_type_mapping: dict[str, RepoType]) -> list[CveWithCommitInfo]:
    result_cve = []

    for cve in cve_with_commit:
        commit_infos = []

        for commit in cve.commits:
            parse_successfully = check_commit_all_file_parsed_successfully(logger, commit)
            if not parse_successfully:
                logger.info(
                    f'[{commit.repo_name}:{commit.commit_hash} {commit.git_url}] some of the files in this commit are not parsed, '
                    f'possible reason: 1. object-c files\t2.complex file that the parser can not parse.')
                continue

            new_repo_name = repo_name_merge(commit.repo_name)
            repo_type = all_repo_type_mapping[new_repo_name]
            commit_files = []

            for f_path in commit.diff_file_paths:
                f_name = trunc_commit_file_name(f_path)
                this_file_path = parsed_commit_cache_dir / new_repo_name / commit.commit_hash / commit.commit_hash / f_name
                parent_file_path = parsed_commit_cache_dir / new_repo_name / commit.commit_hash / commit.parent_commit_hash / f_name
                vulnerable_funcs: list[VulnerableFunction] = []
                non_vulnerable_funcs: list[NonVulnerableFunction] = []
                file_type = get_file_type(repo_type, f_name, this_file_path)

                this_file_funcs = load_from_marshmallow_dataclass_json_file(ExtractedFunction, this_file_path,is_list=True)
                parent_file_funcs = load_from_marshmallow_dataclass_json_file(ExtractedFunction, parent_file_path , is_list=True)


                this_file_func_name_mapping = get_file_functions_name_mapping(this_file_funcs)
                parent_file_func_name_mapping = get_file_functions_name_mapping(parent_file_funcs)

                func_name_intersect = list(this_file_func_name_mapping.keys() & parent_file_func_name_mapping.keys())

                for func_name in func_name_intersect:
                    this_func = this_file_func_name_mapping[func_name]
                    parent_func = parent_file_func_name_mapping[func_name]

                    if this_func.func == parent_func.func:
                        non_vulnerable_funcs.append(
                            NonVulnerableFunction(
                                func_name, this_func.parameter_list_signature, this_func.parameter_list, this_func.return_type, this_func.func, '',
                                {}, None
                            )
                        )
                    else:
                        # function changed, parent function has vulnerable
                        diff_func , diff_line_dict = difflib_diff_func(parent_func.func, this_func.func)

                        vulnerable_funcs.append(
                            VulnerableFunction(
                                func_name,
                                parent_func.parameter_list_signature, parent_func.parameter_list, parent_func.return_type, parent_func.func , '', {}, None,
                                this_func.parameter_list_signature, this_func.parameter_list, this_func.return_type, this_func.func, '' , {},  None ,
                                diff_func, diff_line_dict
                            )
                        )

                if len(vulnerable_funcs) > 0:
                    # If the number of vulnerable functions is zero, some files will be filtered
                    commit_file = CommitFile(f_name,f_path,file_type,vulnerable_funcs,non_vulnerable_funcs)
                    commit_files.append(commit_file)

            if len(commit_files) > 0:
                commit_infos.append(CommitInfo(
                    new_repo_name, commit.commit_msg, commit.commit_hash, commit.parent_commit_hash,commit.commit_date, commit.diff_file_paths, commit_files, commit.git_url
                ))

        if len(commit_infos) > 0:
            cve_dict = asdict(cve)
            cve_dict.pop('commits')
            new_cve = CveWithCommitInfo(**cve_dict, commits=commit_infos) # update commits
            result_cve.append(
                new_cve
            )

    return result_cve

def build_parser():
    parser_list = [
        ParserC(global_logger),
        ParserCpp(global_logger),
    ]
    for parser in parser_list:
        global_logger.info(f"building {parser.parser_name}")

def extract_successful_parsed_commit(using_cache:bool = False) -> list[CveWithCommitInfo]:
    if cve_with_parsed_commit_json_path.exists() and using_cache:
        global_logger.info(f'{cve_with_parsed_commit_json_path} exists, using cache')
        return load_from_marshmallow_dataclass_json_file(CveWithCommitInfo,cve_with_parsed_commit_json_path)

    recorder = ExtractCommitDiffRecorder(parsed_commit_cache_dir)

    if not cve_with_downloaded_commit_json_path.exists():
        global_logger.info(f'{cve_with_downloaded_commit_json_path} not found, run extract_and_download_commit.py to download commits first.')

    cve_with_commit: list[CveWithDownloadedCommitInfo] = load_from_marshmallow_dataclass_json_file(
        CveWithDownloadedCommitInfo, cve_with_downloaded_commit_json_path , is_list=True)

    # step.1 pre-determine the type of language used in project
    all_repo_type_mapping = determine_all_repo_types(cve_with_commit)

    # step.2 extract and parse functions of all file in each commit
    build_parser()
    multiprocessing_apply_data_with_logger(
        partial(parse_all_commit_files, all_repo_type_mapping = all_repo_type_mapping) ,
        cve_with_commit , chunk_mode= True
    )
    global_logger.info('all commit files have benn parsed')
    recorder.record_and_print_raw_info(global_logger,cve_with_commit)

    # step.3 finding commits that successfully parsed, extract vulnerable and non-vulnerable functions
    cve_with_parsed_commit : list[CveWithCommitInfo] = multiprocessing_apply_data_with_logger(
        partial(find_successfully_parsed_commit, all_repo_type_mapping=all_repo_type_mapping),
        cve_with_commit, chunk_mode=True
    )
    save_marshmallow_dataclass_to_json_file(
        CveWithCommitInfo, cve_with_parsed_commit_json_path , cve_with_parsed_commit
    )
    recorder.record_and_print_diff_info(global_logger,cve_with_parsed_commit)

    return cve_with_parsed_commit


def run_filters_with_parsed_commit(cve_with_parsed_commit: list[CveWithCommitInfo]):
    """
        run filters to clean the dataset, and get high quality data.
    """
    global_logger.info('running filters to distill the dataset')
    filter_result = run_filters(cve_with_parsed_commit, [
        TestFileFilter(global_logger),
        LargeChangeFilter(global_logger),
        MultiCveCommitFilter(global_logger),
        OneCveMultipleCommitsByContentDuplicateFilter(global_logger),
        OneCveMultipleCommitsNonVulDuplicateFilter(global_logger),
        RemoveNonVulDuplicateFilter(global_logger),
        RemoveNonVulAppearInVulFilter(global_logger),
        TestFunctionFilter(global_logger),
        LargeNonVulFunctionFilter(global_logger),
        LargeVulFunctionFilter(global_logger),
    ])

    global_logger.info(f'all filters have been run, save result to {cve_with_parsed_and_filtered_commit_json_path}')
    save_marshmallow_dataclass_to_json_file(
        CveWithCommitInfo, cve_with_parsed_and_filtered_commit_json_path , filter_result
    )

def only_run_statistical_filter():
    """
        for debug only
    """

    cve_with_parsed_and_filtered_commit = load_from_marshmallow_dataclass_json_file(
        CveWithCommitInfo, cve_with_parsed_and_filtered_commit_json_path
    )
    run_filters(cve_with_parsed_and_filtered_commit, [
        MetricsGlobalFilter(global_logger),
    ])

def extract_commit_diff():
    cve_with_parsed_commit = extract_successful_parsed_commit(using_cache= True)

    run_filters_with_parsed_commit(cve_with_parsed_commit)



if __name__ == '__main__':
    extract_commit_diff()
