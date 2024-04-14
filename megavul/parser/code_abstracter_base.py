import logging
from abc import ABCMeta, abstractmethod
from pathlib import Path
from typing import Callable

from tree_sitter import Language, Parser, Node

from megavul.parser.parser_util import traverse_tree
from megavul.util.storage import StorageLocation
from megavul.util.utils import build_tree_sitter_language


class CodeAbstracterBase(metaclass=ABCMeta):
    DEBUG_MODE = False
    DEBUG_SAVE_LOCATION = StorageLocation.debug_dir() / "code_abstract.txt"
    DEFAULT_ABSTRACT_CONFIG = {
        'VAR': True, 'COMMENT': True, 'FUNC': False, 'TYPE': False, 'NUMBER': False,
        'FIELD': False, 'STR': False, 'CHAR': False, 'LABEL': False
    }
    ALL_ABSTRACT_TYPES = ['VAR', 'FUNC', 'TYPE', 'NUMBER', 'FIELD', 'STR', 'CHAR', 'COMMENT', 'LABEL', 'ANNOTATION']

    def __init__(self, logger: logging.Logger):
        self.logger = logger

    def __get_language(self, language: str) -> Language:
        return build_tree_sitter_language(language, CodeAbstracterBase.DEBUG_MODE)

    def get_parser(self, language: str) -> Parser:
        parser = Parser()
        parser.set_language(self.__get_language(language))
        return parser

    def abstract_file(self, file_path: Path, language: str):
        file_lines = file_path.open(mode='r', encoding='utf-8-sig').readlines()  # remove u'\ufeff'
        code = ''.join(file_lines)
        return self.abstract_code(code, language)

    @staticmethod
    def debug_abstract_code(code: str, abstract_code: str):
        if CodeAbstracterBase.DEBUG_MODE:
            with CodeAbstracterBase.DEBUG_SAVE_LOCATION.open(mode='a') as f:
                f.write(code)
                f.write('\n')
                f.write('=' * 25 + " ABSTRACT " + '=' * 25)
                f.write('\n')
                f.write(abstract_code)
                f.write('\n' * 10)

    def abstract_code(self, code: str, language: str) -> tuple[str, dict]:
        assert language in self.support_languages
        parser = self.find_parser(language)
        tree = parser.parse(bytes(code, encoding='utf-8'))

        position_map: dict[
            int, list[tuple]] = {}  # row -> list[(col, internal_id, abstract_type, text, need_replace_to_whitespace)]
        abstract_type_map: dict[str, dict[str, str]] = {}

        for abstract_type in CodeAbstracterBase.ALL_ABSTRACT_TYPES:
            abstract_type_map[abstract_type] = {}

        global_internal_id_cnt = 0  # internal id

        def add_to_position_map(row: int, col: int, internal_id: int, abstract_type: str, node_text: str,
                                need_replace_to_whitespace=False):
            nonlocal position_map
            position_map.setdefault(row, [])
            position_map[row].append((col, internal_id, abstract_type, node_text, need_replace_to_whitespace))

        def node_abstract(node: Node, abstract_type: str):
            nonlocal global_internal_id_cnt, position_map, abstract_type_map
            this_type_map = abstract_type_map[abstract_type]
            node_text: str = node.text.decode('utf-8')
            final_abstract_symbol = f"{abstract_type}_{len(this_type_map)}"
            if abstract_type == 'COMMENT':
                final_abstract_symbol = f"/* {abstract_type}_{len(this_type_map)} */"

            global_id = global_internal_id_cnt
            if len(node_text.splitlines()) > 1:  # multiline lines string literal
                node_texts = node_text.splitlines(keepends=False)
                start_row: int = node.start_point[0]
                for row in range(start_row, start_row + len(node_texts)):  # row number
                    col = node.start_point[1] if row == start_row else 0
                    node_text = node_texts[row - start_row]
                    key = f'{node_text}$${global_id}'  # concat internal_id, split lines maybe conflict
                    if key not in this_type_map:
                        this_type_map[key] = final_abstract_symbol
                    if row == start_row:
                        # for multiline text, we only abstract first line, rest of lines are replaced with whitespace
                        add_to_position_map(row, col, global_id, abstract_type, node_text, False)
                    else:
                        # rest of lines
                        add_to_position_map(row, col, global_id, abstract_type, node_text, True)
                global_internal_id_cnt += 1
            else:  # one line string literal
                key = f'{node_text}'
                if key not in this_type_map:
                    this_type_map[key] = final_abstract_symbol
                row, col = node.start_point
                add_to_position_map(row, col, -1, abstract_type, node_text, False)

        for node in traverse_tree(tree):
            self.abstract_node(node, node_abstract, abstract_type_map)

        abstract_code = abstract_code_with_config(
            code, position_map, abstract_type_map, CodeAbstracterBase.DEFAULT_ABSTRACT_CONFIG
        )

        CodeAbstracterBase.debug_abstract_code(code, abstract_code)

        symbol_table = {'position_map': position_map, 'abstract_table': abstract_type_map}
        return abstract_code, symbol_table

    @property
    @abstractmethod
    def support_languages(self) -> list[str]:
        ...

    @abstractmethod
    def find_parser(self, language: str) -> Parser:
        ...

    @abstractmethod
    def abstract_node(self, node: Node, node_abstract: Callable[[Node, str], None],
                      abstract_type_map: dict[str, dict[str, str]]):
        ...


def check_abstract_config(abstract_config: dict):
    all_abstract_types = CodeAbstracterBase.ALL_ABSTRACT_TYPES
    for k in abstract_config.keys():
        if k not in all_abstract_types:
            raise RuntimeError(f"Only support abstract {all_abstract_types}")


def abstract_code_with_config(code: str, position_map: dict[int, list[tuple]],
                              abstract_table: dict[str, dict], abstract_config: dict):
    check_abstract_config(abstract_config)

    def enable_this_type_abstract(abstract_type: str) -> bool:
        nonlocal abstract_config
        if abstract_type in abstract_config and abstract_config[abstract_type] == True:
            return True
        return False

    new_line_of_code = []
    for line, line_of_code in enumerate(code.splitlines(keepends=True)):
        if line not in position_map:
            new_line_of_code.append(line_of_code)
            continue

        items_in_line = position_map[line]
        sorted_items_in_line = sorted(items_in_line, key=lambda x: x[0])  # sort by column

        add_sentinel_line = ''
        last_col = 0
        for item_idx, item in enumerate(sorted_items_in_line):
            # add sentinels and then we can easily replace them all at once
            # for example:
            #   "this is my hello world nicktime!"    [(5,'is'),(23,'nicktime!')]
            #   ------->  this $$$is$$$ my hello world $$$nicktime!$$$
            #   then we replace with sentinels
            this_item_start_col = item[0]
            abstract_type = item[2]
            # print(item)
            this_item_len = len(item[3])
            if not enable_this_type_abstract(abstract_type):
                continue
            add_sentinel_line += line_of_code[last_col:this_item_start_col] + "$$$$" + line_of_code[
                                                                                       this_item_start_col:this_item_start_col + this_item_len] + '$$$$'
            last_col = this_item_start_col + this_item_len
        add_sentinel_line += line_of_code[last_col:]

        final_line = add_sentinel_line
        for item in sorted_items_in_line:
            internal_id = item[1]
            abstract_type = item[2]
            text = item[3]
            need_replace_to_whitespace = item[4]
            key = f'{text}' if internal_id == -1 else f'{text}$${internal_id}'
            if not enable_this_type_abstract(abstract_type):
                continue
            abstract_symbol = abstract_table[abstract_type][key]
            if need_replace_to_whitespace:
                abstract_symbol = ' ' * len(text)
            final_line = final_line.replace(f'$$$${text}$$$$', abstract_symbol)

        new_line_of_code.append(final_line)

    abstract_code = ''.join(new_line_of_code)
    return abstract_code
