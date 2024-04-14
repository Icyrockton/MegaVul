import logging
from abc import ABCMeta, abstractmethod
from functools import cached_property
from pathlib import Path

from timeout_decorator import timeout_decorator
from tree_sitter import Language, Parser, Tree

from megavul.parser.parser_util import ExtractedFunction
from megavul.util.utils import build_tree_sitter_language, save_marshmallow_dataclass_to_json_file


class ParserBase(metaclass=ABCMeta):
    DEBUG_MODE = False

    def __init__(self, logger: logging.Logger):
        self.logger = logger

    @property
    @abstractmethod
    def language_name(self) -> str:
        # tree-sitter-c    ---> c
        # tree-sitter-cpp  ---> cpp
        # tree-sitter-java ---> java
        ...

    @cached_property
    def language(self) -> Language:
        return build_tree_sitter_language(self.language_name, ParserBase.DEBUG_MODE)


    @cached_property
    def parser(self) -> Parser:
        """ set tree-sitter parser """
        parser = Parser()
        parser.set_language(self.language)
        return parser


    def parse_file(self, fp: Path, result_save_path: Path):
        file_lines = fp.open(mode='r',encoding='utf-8-sig').readlines() # remove u'\ufeff'
        file_b = ''.join(file_lines)
        tree = self.parser.parse(bytes(file_b, encoding='utf-8'))
        extracted_funcs = self.parse(tree, file_lines)
        save_marshmallow_dataclass_to_json_file(ExtractedFunction, result_save_path, extracted_funcs)

    @timeout_decorator.timeout(seconds=20)
    @abstractmethod
    def parse(self, tree: Tree, file_lines: list[str]) -> list[ExtractedFunction]:
        ...

    @abstractmethod
    def can_handle_this_language(self, language_name: str) -> bool:
        ...

    ###########  for debug ############
    @property
    def parser_name(self):
        return self.__class__.__name__

    def debug(self,msg:str):
        if ParserBase.DEBUG_MODE:
            self.logger.debug(f'[{self.parser_name}] {msg}')
