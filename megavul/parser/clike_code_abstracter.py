import logging
from pathlib import Path
from tree_sitter import Language, Parser, Node
from megavul.parser.parser_util import traverse_tree
from megavul.util.logging_util import global_logger
from megavul.util.utils import load_dependencies, build_tree_sitter_language
from megavul.util.storage import StorageLocation

C_KEYWORDS = ["auto", "break", "case", "continue", "default", "do",
              "else", "enum", "extern", "for", "goto", "if",
              "register", "return", "sizeof", "static",
              "struct", "switch", "typedef", "union", "unsigned", "volatile", "while"]

class CLikeCodeAbstracter:
    """
        this abstractor is used to abstract c/c++ functions
    """
    DEBUG_MODE = False
    DEBUG_SAVE_LOCATION = StorageLocation.debug_dir() / "code_abstract.txt"
    DEFAULT_ABSTRACT_CONFIG = {
        'VAR': True, 'COMMENT': True, 'FUNC': False, 'TYPE': False, 'NUMBER': False,
        'FIELD': False, 'STR': False, 'CHAR': False, 'LABEL': False
    }
    ALL_ABSTRACT_TYPES = ['VAR', 'FUNC', 'TYPE', 'NUMBER', 'FIELD', 'STR', 'CHAR', 'COMMENT', 'LABEL']

    def __init__(self, logger: logging.Logger):
        self.parser_c = self.get_parser(self.get_language('c'))
        self.parser_cpp = self.get_parser(self.get_language('cpp'))
        self.logger = logger

    def get_language(self, language: str) -> Language:
        return build_tree_sitter_language(language, CLikeCodeAbstracter.DEBUG_MODE)

    def get_parser(self, language) -> Parser:
        parser = Parser()
        parser.set_language(language)
        return parser

    def abstract_file(self, file_path: Path, language: str):
        file_lines = file_path.open(mode='r', encoding='utf-8-sig').readlines()  # remove u'\ufeff'
        code = ''.join(file_lines)
        return self.abstract_code(code, language)

    def abstract_code(self, code: str, language: str) -> tuple[str, dict]:
        assert language in ['c', 'cpp']
        parser = self.parser_c if language == 'c' else self.parser_cpp
        tree = parser.parse(bytes(code, encoding='utf-8'))

        position_map: dict[
            int, list[tuple]] = {}  # row -> list[(col, internal_id, abstract_type, text, need_replace_to_whitespace)]
        abstract_type_map: dict[str, dict[str, str]] = {}

        for abstract_type in CLikeCodeAbstracter.ALL_ABSTRACT_TYPES:
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
            node_type = node.type
            if node_type in ['identifier', 'type_identifier', 'primitive_type',
                             "sized_type_specifier",  'field_identifier',
                             'char_literal', 'number_literal', 'statement_identifier']:
                if node.parent is None or node.parent.type in ['function_declarator', 'qualified_identifier']:
                    # keep function name, we do not abstract function name
                    continue

                node_text = node.text.decode('utf-8')
                if node_text in C_KEYWORDS:
                    # filter parser error, some C keywords are identified as identifier
                    continue
                if node_type == 'primitive_type' and node.parent and node.parent.type == 'sized_type_specifier':
                    # unsigned int , unsigned float , data type
                    continue

                cur_type = 'VAR'
                if node.parent.type in ['call_expression', 'preproc_function_def']:  # function id
                    cur_type = 'FUNC'

                if node_type in ['type_identifier', 'primitive_type', 'sized_type_specifier']:
                    cur_type = 'TYPE'
                elif node_type == 'field_identifier':
                    cur_type = 'FIELD'
                elif node_type == 'statement_identifier':
                    cur_type = 'LABEL'
                elif node_type == 'number_literal':
                    cur_type = 'NUMBER'
                elif node_type == 'char_literal':
                    cur_type = 'CHAR'

                # print(node_text,node_type,cur_class,node.parent.text)
                assert cur_type in abstract_type_map.keys()

                if cur_type == 'FUNC' and node_text in abstract_type_map['VAR']:
                    # function pointer variable
                    cur_type = 'VAR'

                if cur_type == 'VAR' and node_text in abstract_type_map['TYPE']:
                    # some type are identified as identifier
                    cur_type = 'TYPE'

                if cur_type == 'VAR' and node_text in abstract_type_map['FUNC']:
                    # calling some function variables before they are assigned as a value, we define them as variable.
                    cur_type = 'VAR'

                node_abstract(node, cur_type)
            elif node_type == 'string_literal':
                node_abstract(node, 'STR')
            elif node_type == 'comment':
                node_abstract(node, 'COMMENT')

        abstract_code = abstract_code_with_config(
            code, position_map, abstract_type_map, CLikeCodeAbstracter.DEFAULT_ABSTRACT_CONFIG
        )

        if CLikeCodeAbstracter.DEBUG_MODE:
            with CLikeCodeAbstracter.DEBUG_SAVE_LOCATION.open(mode='a') as f:
                f.write(code)
                f.write('=' * 25 + " ABSTRACT " + '=' * 25)
                f.write(abstract_code)
                f.write('\n' * 10)

        symbol_table = {'position_map': position_map, 'abstract_table': abstract_type_map}
        return abstract_code, symbol_table


def check_abstract_config(abstract_config: dict):
    all_abstract_types = CLikeCodeAbstracter.ALL_ABSTRACT_TYPES
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


if __name__ == '__main__':
    abstracter = CLikeCodeAbstracter(global_logger)
    print(abstracter.abstract_code("""
CodingReturnValue LeptonCodec::ThreadState::vp8_decode_thread(unsigned int thread_id,
                                                              UncompressedComponents *const colldata) {
    Sirikata::Array1d<uint32_t, (uint32_t)ColorChannel::NumBlockTypes> component_size_in_blocks;
    BlockBasedImagePerChannel<false> image_data;
    for (int i = 0; i < colldata->get_num_components(); ++i) {
        component_size_in_blocks[i] = colldata->component_size_in_blocks(i);
        image_data[i] = &colldata->full_component_write((BlockType)i);
    }
    Sirikata::Array1d<uint32_t,
                      (size_t)ColorChannel::NumBlockTypes> max_coded_heights
        = colldata->get_max_coded_heights();
    /* deserialize each block in planar order */

    dev_assert(luma_splits_.size() == 2); // not ready to do multiple work items on a thread yet
    int min_y = luma_splits_[0];
    int max_y = luma_splits_[1];
    while(true) {
        RowSpec cur_row = row_spec_from_index(decode_index_++, image_data, colldata->get_mcu_count_vertical(), max_coded_heights);
        if (cur_row.done) {
            break;
        }
        if (cur_row.luma_y >= max_y && thread_id + 1 != NUM_THREADS) {
            break;
        }
        if (cur_row.skip) {
            continue;
        }
        if (cur_row.luma_y < min_y) {
            continue;
        }
        decode_rowf(image_data,
                   component_size_in_blocks,
                   cur_row.component,
                   cur_row.curr_y);
        if (thread_id == 0) {
            colldata->worker_update_cmp_progress((BlockType)cur_row.component,
                                                 image_data[cur_row.component]->block_width() );
        }
        return CODING_PARTIAL;
    }
    return CODING_DONE;
}""", 'cpp')[0])
