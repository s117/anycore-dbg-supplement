from typing import Optional, List

from bashlex import parser, ast
from bashlex.errors import ParsingError

from .utils import fatal, warning


def extract_stdin_file_from_shcmd(shcmd):
    # type: (str) -> Optional[List[str]]
    trees = parser.parse(shcmd)
    stdin_files = []

    class nodevisitor(ast.nodevisitor):
        def __init__(self):
            pass

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
