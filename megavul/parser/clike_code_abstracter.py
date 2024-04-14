import logging
from typing import Callable

from tree_sitter import Node, Parser

from megavul.parser.code_abstracter_base import CodeAbstracterBase
from megavul.util.logging_util import global_logger

C_KEYWORDS = ["auto", "break", "case", "continue", "default", "do",
              "else", "enum", "extern", "for", "goto", "if",
              "register", "return", "sizeof", "static",
              "struct", "switch", "typedef", "union", "unsigned", "volatile", "while"]

class CLikeCodeAbstracter(CodeAbstracterBase):
    """
        this abstractor is used to abstract c/c++ functions
    """
    def __init__(self, logger: logging.Logger):
        super().__init__(logger)
        self.parser_c = self.get_parser('c')
        self.parser_cpp = self.get_parser('cpp')

    @property
    def support_languages(self) -> list[str]:
        return ['c','cpp']

    def find_parser(self, language: str) -> Parser:
        if language == 'c':
            return self.parser_c
        else:
            return self.parser_cpp


    def abstract_node(self, node: Node, node_abstract: Callable[[Node, str], None],abstract_type_map: dict[str, dict[str, str]]):
        node_type = node.type
        if node_type in ['identifier', 'type_identifier', 'primitive_type',
                         "sized_type_specifier", 'field_identifier',
                         'char_literal', 'number_literal', 'statement_identifier']:
            if node.parent is None or node.parent.type in ['function_declarator', 'qualified_identifier']:
                # keep function name, we do not abstract function name
                return

            node_text = node.text.decode('utf-8')
            if node_text in C_KEYWORDS:
                # filter parser error, some C keywords are identified as identifier
                return
            if node_type == 'primitive_type' and node.parent and node.parent.type == 'sized_type_specifier':
                # unsigned int , unsigned float , data type
                return

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
