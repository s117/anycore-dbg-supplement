import os

import click

from ..libsyscall.analyzer.scall_trace_analyzer import scall_trace_analyzer


@click.command()
@click.argument("input_file", type=click.File())
@click.option('--echo', is_flag=True, help='echo the decoded scall trace.')
# @click.option("-c", '--cwd', "cwd_path", type=click.Path(exists=True),
#               help='the CWD used for evaluate out-of-tree file access.')
def main(input_file, echo):
    cwd_path = os.path.abspath(os.path.dirname(input_file.name))

    trace_analyzer = scall_trace_analyzer(cwd_path)
    strace_str = input_file.read()

    trace_analyzer.parse_strace_str(strace_str)
    for t in trace_analyzer.syscalls:
        print(str(t))


if __name__ == '__main__':
    main()
