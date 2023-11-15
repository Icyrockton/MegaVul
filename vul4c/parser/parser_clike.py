import logging
from abc import ABCMeta, abstractmethod
from tree_sitter import Language, Parser, TreeCursor, Tree, Node
import re
from pathlib import Path

from vul4c.parser.parser_base import ParserBase
from vul4c.parser.parser_util import ExtractedFunction
from vul4c.util.utils import save_marshmallow_dataclass_to_json_file, build_tree_sitter_language
from functools import cached_property
import timeout_decorator


class ParserCLike(ParserBase,metaclass=ABCMeta):

    def parse_file(self, fp: Path, result_save_path: Path):
        if result_save_path.exists(): # cache
            return

        file_lines = fp.open(mode='r',encoding='utf-8-sig').readlines() # remove u'\ufeff'
        remove_comment_src = ParserCLike.replace_comments_with_whitespace(''.join(file_lines))
        try:
            file_b = ParserCLike.remove_preprocessor(remove_comment_src)
        except Exception as e:
            self.logger.debug(f'remove preprocessor failed for {fp} , rollback to raw file')
            file_b = ''.join(file_lines)
        tree = self.parser.parse(bytes(file_b, encoding='utf-8'))
        try:
            extracted_funcs = self.parse(tree, file_lines)
            save_marshmallow_dataclass_to_json_file(ExtractedFunction, result_save_path, extracted_funcs)
        except timeout_decorator.TimeoutError as e:
            self.logger.debug(f'{fp} file parse time out')

        # save extracted funcs

    @staticmethod
    def remove_preprocessor(code: str) -> str:
        """  remove preprocessor to temporarily solve https://github.com/tree-sitter/tree-sitter-c/issues/70 """
        code = code.splitlines(True)
        res_line = []
        new_code = []
        if_nif_stack = []
        nested_level = 0
        encounter_else_stack = []
        # remove `else`,`elif` block content
        for line in code:
            strip_line = line.strip()
            if re_res := re.match(r'^#[ \t]*(?P<macro>ifdef|ifndef|else|elif|endif|if)', strip_line):
                macro = re_res.group('macro')
                if macro in ['ifdef', 'ifndef', 'if']:
                    nested_level += 1
                    if_nif_stack.append(nested_level)
                elif macro in ['else', 'elif']:
                    if (len(encounter_else_stack) > 0 and encounter_else_stack[-1] != nested_level) or len(
                            encounter_else_stack) == 0:
                        encounter_else_stack.append(nested_level)
                elif macro in ['endif']:
                    previous_level = if_nif_stack.pop()
                    nested_level -= 1
                    if len(encounter_else_stack) > 0 and encounter_else_stack[-1] == previous_level:
                        encounter_else_stack.pop()

            if len(encounter_else_stack) > 0 and encounter_else_stack[-1] == nested_level:
                new_code.append(' ' * (len(line) - 1) + '\n')
            else:
                new_code.append(line)

        code = new_code
        # remove macro
        for line in code:
            strip_line = line.strip()
            if re_res := re.match(r'^#[ \t]*(ifdef|ifndef|else|elif|endif|if)', strip_line):
                res_line.append(' ' * (len(line) - 1) + '\n')
            else:
                res_line.append(line)

        assert len(res_line[-1]) == len(line), "remove preprocessor failed"
        return ''.join(res_line)

    @staticmethod
    def cal_relative_point(start_point, point) -> tuple[int,int]:
        if start_point[0] == point[0]:  # save row
            return point[0] - start_point[0], point[1] - start_point[1]
        else:
            return point[0] - start_point[0], point[1]

    SPECIAL_IDENTIFIER = '$$$$$ID$$$$$'

    @staticmethod
    def multiline_replace(lines: list[str], start_point: tuple, replace_id: str):
        prefix_line = lines[:start_point[0]]
        postfix_line = lines[start_point[0] + 1:]
        modify_line = lines[start_point[0]]
        modify_line = modify_line[:start_point[1]] + modify_line[start_point[1]:].replace(replace_id,
                                                                                          ParserCLike.SPECIAL_IDENTIFIER,
                                                                                          1)  # replace one time
        lines = prefix_line + [modify_line] + postfix_line
        return lines

    @staticmethod
    def replace_comments_with_whitespace(csrc: str) -> str:
        regex = r'(\".*?\"|\'.*?\')|(/\*.*?\*/|//[^\r\n]*$)'
        old_len = len(csrc)

        def replace_block_comment(x: re.Match) -> str:
            if x.group(2) is not None:
                match = x.group()
                replace_str = list(' ' * len(match))
                for idx, c in enumerate(match):
                    if c == '\n':
                        replace_str[idx] = '\n'
                replace_str = ''.join(replace_str)
                return replace_str
            else:
                return x.group(1)

        csrc = re.sub(regex, replace_block_comment, csrc, flags=re.MULTILINE | re.DOTALL)

        assert old_len == len(csrc)

        return csrc

    @staticmethod
    def remove_block_comments(csrc: str) -> str:
        """ Remove block comments from c source string - /* */ """
        regex = r'/\*.*?\*/'
        matches = re.findall(regex, csrc, re.DOTALL)
        for match in matches:
            csrc = csrc.replace(match, '')

        return csrc

    @staticmethod
    def remove_single_line_comments(csrc: str) -> str:
        """ Remove single line comments from c source string - // """
        regex = r'//.*$'
        csrc = re.sub(regex, '', csrc, flags=re.MULTILINE)
        return csrc

    @staticmethod
    def remove_comments(csrc: str) -> str:
        '''Remove comments from a c source file'''
        content = csrc[:]
        content = ParserCLike.remove_block_comments(content)
        content = ParserCLike.remove_single_line_comments(content)
        return content
