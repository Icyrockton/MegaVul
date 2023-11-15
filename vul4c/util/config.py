from vul4c.util.storage import StorageLocation
import yaml

__all__ = ['config_file']
def read_config_file() -> dict:
    config_path = StorageLocation.config_path()
    github_token_path = StorageLocation.github_token_path()
    if not config_path.exists():
        raise Exception("config.yaml config file does not exist")

    if not github_token_path.exists():
        raise Exception("github_token.txt file does not exist")

    github_tokens = []
    for token in github_token_path.open(mode='r').readlines():
        if token.startswith('ghp') or token.startswith('gho'):
            github_tokens.append(token.strip())
        else:
            raise Exception(f'invalid github token {token}')

    if len(github_tokens) < 4:
        raise Exception('at least 4 github tokens are required')

    config = yaml.safe_load(config_path.open(mode='r'))
    config['github'] = github_tokens
    return config

config_file = read_config_file()