from dataclasses import dataclass
from typing import Iterator
from tree_sitter import TreeCursor, Tree, Node

@dataclass
class ExtractedFunction:
    func_name:str
    parameter_list_signature:str
    parameter_list:list
    return_type:str
    func:str


def split_from_file(file_lines: list[str], start_point: tuple, end_point: tuple):
    content = file_lines[start_point[0]:end_point[0] + 1]
    if len(content) == 1:
        content[0] = content[0][start_point[1]:end_point[1]]
    else:
        content[0] = content[0][start_point[1]:]
        content[-1] = content[-1][:end_point[1]]
    return content

def split_from_file_maybe_flatten(file_lines: list[str], start_point: tuple, end_point: tuple):
    res = split_from_file(file_lines, start_point, end_point)
    return res[0] if len(res) == 1 else res

def node_split_from_file(file_lines: list[str], node :Node) -> str | list[str]:
    res = split_from_file(file_lines, node.start_point, node.end_point)
    return res[0] if len(res) == 1 else res

def traverse_cursor(cursor: TreeCursor) -> Iterator[Node]:
    reached_root = False
    while reached_root == False:
        yield cursor.node

        if cursor.goto_first_child():
            continue

        if cursor.goto_next_sibling():
            continue

        retracing = True
        while retracing:
            if not cursor.goto_parent():
                retracing = False
                reached_root = True

            if cursor.goto_next_sibling():
                retracing = False

def traverse_tree(tree: Tree) -> Iterator[Node]:
    cursor = tree.walk()
    return traverse_cursor(cursor)