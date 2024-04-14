from typing import Tuple

from megavul.parser.parser_base import ParserBase
from megavul.parser.parser_util import ExtractedFunction, traverse_tree, node_split_from_file
from tree_sitter import Tree, Node


class ParserJava(ParserBase):

    @property
    def language_name(self) -> str:
        return 'java'

    def find_method_nodes(self, tree: Tree) -> list[Node]:
        func_nodes: list[Node] = []
        for i in traverse_tree(tree):
            if i.type == 'method_declaration':
                func_nodes.append(i)

        # if a function nested in a function definition, filter it
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
        func_nodes = self.find_method_nodes(tree)
        extracted_funcs : list[ExtractedFunction] = []

        for node in func_nodes:
            func = self.traverse_method_declaration(node, file_lines)
            if func is not None:
                extracted_funcs.append(func)

        return extracted_funcs

    def can_handle_this_language(self, language_name: str) -> bool:
        return language_name.lower() == 'java'

    def traverse_method_declaration(self, func_node: Node, file_lines : list[str]) :
        cursor = func_node.walk()

        return_type_node = cursor.node.child_by_field_name('type')
        assert return_type_node is not None
        return_type = node_split_from_file(file_lines, return_type_node)

        method_name_node = cursor.node.child_by_field_name('name')
        assert method_name_node is not None
        method_name = node_split_from_file(file_lines, method_name_node)

        parameter_list = []
        parameter_list_node = cursor.node.child_by_field_name('parameters')
        parameter_list_cursor = parameter_list_node.walk()
        parameter_list_cursor.goto_first_child()
        while True:
            if parameter_list_cursor.node.type == 'formal_parameter':
                parameter_list.append(self.traverse_parameter_declaration(parameter_list_cursor.node,file_lines))
            elif parameter_list_cursor.node.type == 'spread_parameter':
                # void method(Object... a)
                parameter_list.append(self.traverse_spread_parameter_declaration(parameter_list_cursor.node,file_lines))

            if not parameter_list_cursor.goto_next_sibling():
                break

        compose_signature = ''
        for i, p in enumerate(parameter_list):
            if i > 0:
                compose_signature += ','
            compose_signature += f'{p[0]} {p[1]}'

        compose_signature = f'({compose_signature})'

        func = node_split_from_file(file_lines, func_node)
        func = ''.join(func)

        self.debug('=' * 80)
        self.debug(f'method name  : {method_name}')
        self.debug(f'parameters sig : {compose_signature}')
        self.debug(f'parameters     : {parameter_list}')
        self.debug(f'return type    : {return_type}')
        self.debug('=' * 80)

        return ExtractedFunction(method_name, compose_signature, parameter_list, return_type,
                                 func)

    def traverse_parameter_declaration(self, node:Node, file_lines:list[str]) -> Tuple[str, str, int]:
        type = node_split_from_file(file_lines,node.child_by_field_name('type'))
        id = node_split_from_file(file_lines,node.child_by_field_name('name'))
        return type,id,-1

    def traverse_spread_parameter_declaration(self, node:Node, file_lines:list[str] ) -> Tuple[str, str, int]:
        cursor = node.walk()
        cursor.goto_first_child()
        type  : str | None = None
        id : str | None= None

        while True:
            n = cursor.node
            if n.type in ['type_identifier','generic_type','integral_type','floating_point_type','scoped_type_identifier','array_type']:
                type = node_split_from_file(file_lines,n)
            elif n.type == 'variable_declarator':
                id = node_split_from_file(file_lines,n)

            if not cursor.goto_next_sibling():
                break

        assert type is not None
        assert id is not None
        return f'{type}...' , id , -1