import re
from pathlib import Path
from tree_sitter import Language, Parser, TreeCursor, Tree, Node
from vul4c.parser.parser_clike import ParserCLike
from vul4c.parser.parser_util import ExtractedFunction, traverse_tree, node_split_from_file, split_from_file, traverse_cursor, \
    split_from_file_maybe_flatten
from typing import Optional, Tuple
from vul4c.util.logging_util import global_logger


class ParserCpp(ParserCLike):
    @property
    def language_name(self) -> str:
        return 'cpp'

    def can_handle_this_language(self, language_name: str) -> bool:
        return language_name.lower() in ['cpp']

    def traverse_function_definition(self, func_node: Node , file_lines: list[str]) -> Optional[ExtractedFunction]:
        cursor = func_node.walk()

        # in CPP the function return type may be `null` in class constructor
        return_type_node = cursor.node.child_by_field_name('type')
        return_type = None
        if return_type_node is not None:
            return_type = node_split_from_file(file_lines,return_type_node)
        cursor.goto_first_child()

        func_name = None
        parameter_list_signature = None
        destruction_ptr_return_type_level = 0
        parameter_list_node = None

        while True:
            node_type = cursor.node.type

            if node_type == 'pointer_declarator':
                destruction_ptr_return_type_level += 1
                while True:
                    cursor.goto_first_child()
                    if cursor.node.type != 'pointer_declarator':
                        break
                    destruction_ptr_return_type_level += 1

            if node_type == 'function_declarator':
                cursor.goto_first_child()
                while True:
                    declarator_type = cursor.node.type
                    if declarator_type == 'identifier':
                        func_name = node_split_from_file(file_lines,cursor.node)
                    elif declarator_type in ['qualified_identifier', 'destructor_name', 'field_identifier',
                                             'operator_name']:
                        # e.g. NameSpace::Scanner::foo
                        func_name = node_split_from_file(file_lines, cursor.node)
                    elif declarator_type == 'template_function':
                        # e.g. bool foo<A>
                        func_name = node_split_from_file(file_lines,cursor.node.child_by_field_name('name'))
                    elif declarator_type == 'parameter_list':
                        parameter_list_node = cursor.node
                        parameter_list_signature = node_split_from_file(file_lines, cursor.node)
                    if not cursor.goto_next_sibling():
                        break
                cursor.goto_parent()

            if not cursor.goto_next_sibling():
                break

        if parameter_list_node is None:
            self.debug('[ERROR] this function missing parameter list, skip')
            return None

        parameter_list = []
        parameter_list_cursor = parameter_list_node.walk()
        parameter_list_cursor.goto_first_child()
        while True:
            # print('=================')
            # print(parameter_list_cursor.node.type,parameter_list_cursor.node.text)
            if parameter_list_cursor.node.type == 'parameter_declaration':
                # extract all parameter
                parameter_list.append(self.traverse_parameter_declaration(parameter_list_cursor.node,file_lines))
            elif parameter_list_cursor.node.type == 'variadic_parameter_declaration':
                # int main(...)   int main(Tail...)
                parameter_list.append(self.traverse_variadic_parameter_declaration(parameter_list_cursor.node,file_lines))
            elif parameter_list_cursor.node.type == 'optional_parameter_declaration':
                parameter_list.append(self.traverse_optional_parameter_declaration(parameter_list_cursor.node,file_lines))

            if not parameter_list_cursor.goto_next_sibling():
                break

        compose_signature = ''
        for i, p in enumerate(parameter_list):
            if i > 0:
                compose_signature += ','
            if p[1] is None:
                compose_signature += p[0]
            else:
                insert_idx = p[2]
                compose_signature += p[0][:insert_idx] + p[1] + p[0][insert_idx:]
            if len(p) == 4:  # default parameter default value
                compose_signature += p[3]
        compose_signature = f'({compose_signature})'


        if destruction_ptr_return_type_level != 0:
            return_type += '*' * destruction_ptr_return_type_level

        if type(parameter_list_signature) is str:
            parameter_list_signature = [parameter_list_signature]

        if type(parameter_list_signature) is list:  # the parameter_list_signature may be span multilines, so the returned parameter_list_signature is `list` type
            parameter_list_signature = list(map(lambda x: ParserCpp.remove_comments(x), parameter_list_signature))
            parameter_list_signature = ''.join(parameter_list_signature)

            # remove multiline comment again
            parameter_list_signature = ParserCpp.remove_comments(parameter_list_signature)

        parameter_list_signature = parameter_list_signature.replace('\n', '').replace('\t', ' ')
        parameter_list_signature = ' '.join(
            parameter_list_signature.split())  # remove multiple whitespace with single whitespace

        if func_name is None:
            self.debug('[Function Name is None] this function missing function name')
            return None
        elif type(func_name) is list:
            func_name = ''.join(func_name)

        if return_type is None:
            return_type = func_name
            if return_type.startswith('~'):  # destructor name
                return_type = ''

        func = node_split_from_file(file_lines, func_node)
        func = ''.join(func)


        # parameter_list_signature = parameter_list_signature[1:-1] # remove bracket
        self.debug('=' * 80)
        self.debug(f'function name  : {func_name}')
        self.debug(f'parameters sig : {parameter_list_signature}')
        self.debug(f'parameters     : {parameter_list}')
        self.debug(f'return type    : {return_type}')
        self.debug('=' * 80)

        assert func_name is not None and parameter_list_signature is not None and return_type is not None

        if compose_signature.replace(' ', '') != parameter_list_signature.replace(' ', ''):
            self.debug(f'[Signature check error] [{compose_signature}] != [{parameter_list_signature}]')
            return

        return ExtractedFunction(func_name, parameter_list_signature, parameter_list, return_type,
                                 func)


    def traverse_optional_parameter_declaration(self, pd_cursor_node: Node, file_lines: list[str]) -> Tuple[str, str, int, str]:
        pd_cursor = pd_cursor_node.walk()
        pd_start_point, pd_end_point = pd_cursor.node.start_point, pd_cursor.node.end_point
        pd_lines = split_from_file(file_lines ,pd_start_point, pd_end_point, )
        id_node = pd_cursor_node.child_by_field_name('declarator')
        id = None
        if id_node is not None:
            while id_node.type == 'pointer_declarator':
                id_node = id_node.children[1]
            id = node_split_from_file(file_lines, id_node)
            pd_lines = ParserCpp.multiline_replace(pd_lines,
                                              ParserCpp.cal_relative_point(pd_start_point, id_node.start_point), id)

        pd_lines = ''.join(pd_lines).replace('\n', '').replace('\t', ' ')
        pd_lines = ParserCpp.remove_comments(pd_lines)
        default_value = None
        if (re_res := re.search(r'=.*', pd_lines)) is not None:
            default_value = re_res.group()
        type = pd_lines.replace(self.SPECIAL_IDENTIFIER, '').replace(default_value, '')
        type = type.strip()
        assert default_value is not None
        return type, id, pd_lines.index(self.SPECIAL_IDENTIFIER) if id is not None else -1, default_value


    def traverse_variadic_parameter_declaration(self, pd_cursor_node: Node,  file_lines: list[str]) -> Tuple[str, str, int]:
        if ''.join(node_split_from_file(file_lines,pd_cursor_node)).replace(' ', '') == '...':
            return '...', '', -1
        pd_cursor = pd_cursor_node.walk()
        pd_start_point, pd_end_point = pd_cursor.node.start_point, pd_cursor.node.end_point
        pd_lines = split_from_file(file_lines, pd_start_point, pd_end_point)

        id = None
        found_identifier = False
        for node in traverse_cursor(pd_cursor):
            if node.type == 'identifier':
                id = split_from_file_maybe_flatten(file_lines,node.start_point, node.end_point)  # must be str ,not list
                id_start = ParserCpp.cal_relative_point(pd_start_point, node.start_point)
                found_identifier = True

        if found_identifier:
            pd_lines = ParserCpp.multiline_replace(pd_lines, id_start, id)
        else:
            pass

        pd_lines = ''.join(pd_lines).replace('\n', '').replace('\t', ' ')
        insert_index = -1
        if found_identifier:
            insert_index = pd_lines.index(ParserCpp.SPECIAL_IDENTIFIER)
            type = pd_lines.replace(ParserCpp.SPECIAL_IDENTIFIER, '', 1)
        else:
            type = pd_lines

        type = type.strip()
        return type, id, insert_index


    def traverse_parameter_declaration(self, pd_cursor_node: Node, file_lines: list[str]) -> Tuple[str, str, int]:
        pd_cursor = pd_cursor_node.walk()
        pd_start_point, pd_end_point = pd_cursor.node.start_point, pd_cursor.node.end_point
        pd_lines = split_from_file(file_lines,pd_start_point, pd_end_point)

        id = None
        found_identifier = False
        id_start : tuple[int,int]
        for node in traverse_cursor(pd_cursor):
            if node.type == 'identifier':
                # find the last identifier.  we me face `char __user *optval` , __user will be recognized as identifier
                assert node.start_point[0] == node.end_point[0]
                id = split_from_file_maybe_flatten(file_lines,node.start_point, node.end_point)  # must be str ,not list
                id_start = ParserCLike.cal_relative_point(pd_start_point, node.start_point)
                found_identifier = True
            elif node.type == 'parameter_list':
                break

        if found_identifier:
            pd_lines = ParserCLike.multiline_replace(pd_lines, id_start, id)

        # merge pd_lines to one line
        pd_lines = ''.join(pd_lines).replace('\n', '').replace('\t', ' ')
        pd_lines = ParserCLike.remove_comments(pd_lines)
        pd_lines = ' '.join(pd_lines.split())

        insert_index = -1
        if found_identifier:
            insert_index = pd_lines.index(ParserCLike.SPECIAL_IDENTIFIER)
            type = pd_lines.replace(ParserCLike.SPECIAL_IDENTIFIER, '', 1)
        else:
            type = pd_lines

        type = type.strip()
        assert type is not None
        return type, id, insert_index



    def find_function_nodes(self, tree: Tree) -> list[Node]:
        func_nodes: list[Node] = []
        for i in traverse_tree(tree):
            if i.type == 'function_definition':
                func_nodes.append(i)

        # if a function nested in a function definition , filter it
        result_func_nodes = []
        for i, s in enumerate(func_nodes):
            need_add = True
            for j, other_s in enumerate(func_nodes):
                if i != j:
                    if other_s.start_point[0] <= s.start_point[0] and other_s.end_point[0] >= s.end_point[0]:
                        need_add = False
            if need_add:
                result_func_nodes.append(s)

        return result_func_nodes

    def parse(self, tree: Tree, file_lines: list[str]) -> list[ExtractedFunction]:
        extracted_funcs = []

        func_nodes = self.find_function_nodes(tree)

        for node in func_nodes:
            func = self.traverse_function_definition(node, file_lines)
            if func is not None:
                extracted_funcs.append(func)

        return extracted_funcs




if __name__ == '__main__':
    ...

