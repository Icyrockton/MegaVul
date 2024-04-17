import json
from pathlib import Path
from megavul.parser.code_abstracter_base import abstract_code_with_config

graph_dir = Path('../megavul/storage/result/java/graph')

with Path("../megavul/storage/result/java/megavul.json").open(mode='r') as f:
    megavul = json.load(f)
    item = megavul[1]

    code = item['func_before']
    symbol_table = item['abstract_symbol_table_before']
    position_map = symbol_table['position_map']
    abstract_table = symbol_table['abstract_table']

    ABSTRACT_CONFIG = {
        'VAR': True, 'COMMENT': True, 'FUNC': False, 'TYPE': True, 'NUMBER': False,
        'FIELD': False, 'STR': False, 'CHAR': False, 'LABEL': False
    }

    abstract_code = abstract_code_with_config(
        code, position_map, abstract_table, ABSTRACT_CONFIG
    )

    print(code)
    print('=' * 20 + ' ABSTRACT ' + '=' * 20)
    print(abstract_code)
