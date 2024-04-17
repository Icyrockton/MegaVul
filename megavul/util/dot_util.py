from dataclasses import dataclass
import os
import tempfile
import subprocess
from pathlib import Path
from megavul.util.utils import read_json_from_local

__all__ = ['DotGraphGenerator','JoernGraphGenerator']

def escape_string(str):
    s = ""
    for c in str:
        c = ord(c)
        if c == ord('"'):
            s += "&quot;"
        elif c == ord('<'):
            s += "&lt;"
        elif c == ord('>'):
            s += "&gt;"
        elif c == ord('&'):
            s += "&amp;"
        elif c <= 0x9F and (c >= 0x7F or (c >> 5 == 0)):
            s += f"\\0{oct(c)[2:]}"
        else:
            s += chr(c)
    return s


@dataclass
class DotEdge:
    src: int
    dst: int
    label: str

    def edge_to_dot(self):
        return f' "{self.src}" -> "{self.dst}" {"" if self.label is None else escape_string(self.label)}'


@dataclass
class DotNode:
    id: int
    label: str | None

    def node_to_dot(self):
        if self.label is None:
            return f'"{self.id}"'
        return f'"{self.id}" [label = <{escape_string(self.label)}>]'


class DotGraphGenerator:
    def __init__(self, name="Test"):
        self.name = name
        self.nodes: [DotNode] = []
        self.edges: [DotEdge] = []

    def node(self, id: int, label: str | None = None):
        self.nodes.append(DotNode(id, label))

    def edge(self, src: int, dst: int, label: str | None = None):
        self.edges.append(DotEdge(src, dst, label))

    def to_dot_file(self):
        s = f'digraph "{self.name}" {{  \n'
        for n in self.nodes:
            n: DotNode
            s += f"{n.node_to_dot()}\n"
        for e in self.edges:
            e: DotEdge
            s += f"{e.edge_to_dot()}\n"
        s += "\n}\n"
        return s

    def open_in_browser(self):
        """
            make sure you have installed xdg-open in your system
        """
        graph = self.to_dot_file()
        with tempfile.NamedTemporaryFile(mode='w', suffix='.dot', delete=False) as dot_f:
            with tempfile.NamedTemporaryFile(mode='w', suffix='.svg', delete=False) as svg_f:
                dot_tmp_file_path = dot_f.name
                svg_tmp_file_path = svg_f.name
                dot_f.write(graph)
                dot_f.close()  # flush write content
                p = subprocess.run(f"dot -Tsvg {dot_tmp_file_path} -o {svg_tmp_file_path}", shell=True, check=True)
                print(f'Open dot file {svg_tmp_file_path}')
                os.system(f"xdg-open {svg_tmp_file_path}")


_JOERN_EDGE_LABEL_TYPES = ['ARGUMENT', 'AST', 'BINDS', 'CALL', 'CDG', 'CFG', 'CONDITION',
                           'CONTAINS', 'DOMINATE', 'EVAL_TYPE', 'PARAMETER_LINK',
                           'POST_DOMINATE', 'REACHING_DEF', 'RECEIVER', 'REF', 'SOURCE_FILE']


class JoernGraphGenerator:
    def __init__(self, graph_file_path: Path):
        graph = read_json_from_local(graph_file_path)
        assert 'nodes' in graph and 'edges' in graph
        self.nodes = graph['nodes']
        self.edges = graph['edges']

    def __filter_edge(self, edges: list, edge_type: str | None):
        assert edge_type in _JOERN_EDGE_LABEL_TYPES, f"Edge type {edge_type} is not supported, support edge type: {_JOERN_EDGE_LABEL_TYPES}"
        if edge_type is None: return
        return list(filter(lambda x: x['etype'] == edge_type, edges))

    def create_dot_graph(self, edge_type: str | None = None) -> DotGraphGenerator:
        edges = self.__filter_edge(self.edges, edge_type)
        nodes = []
        # remove some node that do not exist in edge
        appear_nodes = set([
            item
            for sub_tuple in [(e['inNode'], e['outNode']) for e in edges] for item in sub_tuple
        ])
        for n in self.nodes:
            if n['id'] in appear_nodes:
                nodes.append(n)

        graph = DotGraphGenerator()
        for n in nodes:
            graph.node(n['id'],
                       f"{n['_label']}  {n['name'] if 'name' in n.keys() else ''}  {n['code'] if 'code' in n.keys() else ''}")
        for e in edges:
            graph.edge(e['inNode'], e['outNode'])
        return graph

    def create_and_show_dot_graph(self, edge_type: str | None = None):
        g = self.create_dot_graph(edge_type)
        g.open_in_browser()
