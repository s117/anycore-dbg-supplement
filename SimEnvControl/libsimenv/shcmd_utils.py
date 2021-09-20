from typing import Optional, List

from bashlex import parser, ast
from bashlex.errors import ParsingError

from .utils import fatal, warning


def extract_stdin_file_from_shcmd(shcmd):
    # type: (str) -> Optional[List[str]]
    trees = parser.parse(shcmd)
    stdin_files = []

    class nodevisitor(ast.nodevisitor):
        def visitredirect(self, n, input, type, output, heredoc):
            if type == "<" and len(output.parts) == 0:
                stdin_files.append(output.word)
            else:
                warning("Warning: command [%s] contains non-resolvable stdin source." % shcmd)

    try:
        for tree in trees:
            visitor = nodevisitor()
            visitor.visit(tree)
        return stdin_files
    except ParsingError:
        return None


def add_prefix_to_stdin_file_in_shcmd(shcmd, prefix):
    # type: (str, str) -> Optional[str]
    trees = parser.parse(shcmd)
    insert_positions = []

    class nodevisitor(ast.nodevisitor):
        def visitredirect(self, n, input, type, output, heredoc):
            if type == "<" and len(output.parts) == 0:
                insert_positions.append(output.pos[0])
            else:
                print("Warning: command [%s] contains non-resolvable stdin source." % shcmd)

    try:
        for tree in trees:
            visitor = nodevisitor()
            visitor.visit(tree)
    except ParsingError:
        return None

    insert_positions.sort(reverse=True)
    result_cmd = shcmd
    for ins_pos in insert_positions:
        # result_cmd = f"{result_cmd[:ins_pos]}{prefix}{result_cmd[ins_pos:]}"
        result_cmd = "".join((result_cmd[:ins_pos], prefix, result_cmd[ins_pos:]))
    return result_cmd
