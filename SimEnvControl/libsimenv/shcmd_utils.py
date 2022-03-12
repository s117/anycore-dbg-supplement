import os
from typing import Optional, List

from bashlex import parser, ast
from bashlex.errors import ParsingError

from .utils import warning


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


def add_base_to_stdin_file_in_shcmd(shcmd, root, cwd):
    # type: (str, str, str) -> str
    trees = parser.parse(shcmd)
    insert_positions = []

    class nodevisitor(ast.nodevisitor):
        def visitredirect(self, n, input, type, output, heredoc):
            if type == "<" and len(output.parts) == 0:
                insert_positions.append((output.pos[0], output.word))
            else:
                print("Warning: command [%s] contains non-resolvable stdin source." % shcmd)

    for tree in trees:
        visitor = nodevisitor()
        visitor.visit(tree)

    insert_positions.sort(key=lambda _: _[0], reverse=True)
    result_cmd = shcmd
    for ins_pos, word in insert_positions:
        if os.path.isabs(word):
            base = root
        else:
            base = root + cwd
            if not base.endswith(os.path.sep):
                base += os.path.sep

        result_cmd = f"{result_cmd[:ins_pos]}{base}{result_cmd[ins_pos:]}"

    return result_cmd
