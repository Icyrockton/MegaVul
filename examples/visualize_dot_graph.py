import json
from pathlib import Path
from megavul.util.dot_util import JoernGraphGenerator

graph_dir = Path('../megavul/storage/result/java/graph')

with Path("../megavul/storage/result/java/megavul_simple.json").open(mode='r') as f:
    megavul = json.load(f)
    item = megavul[1]
    graph_file_path = graph_dir / item['func_graph_path_before']
    joern_graph = JoernGraphGenerator(graph_file_path)

    # support edge types
    # ['ARGUMENT', 'AST', 'BINDS', 'CALL', 'CDG', 'CFG', 'CONDITION',
    #  'CONTAINS', 'DOMINATE', 'EVAL_TYPE', 'PARAMETER_LINK',
    #  'POST_DOMINATE', 'REACHING_DEF', 'RECEIVER', 'REF', 'SOURCE_FILE']

    # xdg-open will open dot file in your browser, make sure you have installed it!
    joern_graph.create_and_show_dot_graph('AST')