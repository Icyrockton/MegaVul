from pathlib import Path
from typing import Callable

def check_path_exist_or_create(path: Path):
    if not path.exists():
        path.mkdir(parents=True, exist_ok=True)


def path_exists_checker(func: Callable[..., Path]) -> Callable[..., Path]:
    def wrapper_func(*args, **kwargs) -> Path:
        return_val = func(*args, **kwargs)
        check_path_exist_or_create(return_val)
        return return_val

    return wrapper_func


class StorageLocation:

    @staticmethod
    def base_dir() -> Path:
        return Path(__file__).parent.parent

    @staticmethod
    @path_exists_checker
    def storage_dir() -> Path:
        return StorageLocation.base_dir() / 'storage'

    @staticmethod
    @path_exists_checker
    def result_dir() -> Path:
        return StorageLocation.storage_dir() / 'result'

    @staticmethod
    @path_exists_checker
    def debug_dir() -> Path:
        return StorageLocation.result_dir() / 'debug'


    @staticmethod
    @path_exists_checker
    def cache_dir() -> Path:
        return StorageLocation.storage_dir() / 'cache'

    @staticmethod
    @path_exists_checker
    def create_cache_dir(name: str) -> Path:
        return StorageLocation.cache_dir() / name

    @staticmethod
    @path_exists_checker
    def logging_dir() -> Path:
        return StorageLocation.storage_dir() / 'logging'


    @staticmethod
    @path_exists_checker
    def tree_sitter_dir() -> Path:
        return StorageLocation.base_dir() / 'tree-sitter'

    @staticmethod
    def joern_dir() -> Path:
        return StorageLocation.base_dir() / 'joern'

    @staticmethod
    def joern_script_path():
        return StorageLocation.base_dir() / 'MegaVulGraphGenerateTest.scala'

    @staticmethod
    def config_path():
        return StorageLocation.base_dir() / 'config.yaml'

    @staticmethod
    def github_token_path():
        return StorageLocation.base_dir() / 'github_token.txt'

