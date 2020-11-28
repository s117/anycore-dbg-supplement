import os

import click

from SyscallAnalysis.libsyscall.analyzer.syscall_trace_constructor import SyscallTraceConstructor
from SyscallAnalysis.libsyscall.analyzer.file_usage import stat_file_usage


@click.command()
@click.argument("input_file", type=click.File())
@click.option('--echo', is_flag=True, help='echo the decoded scall trace.')
# @click.option("-c", '--cwd', "cwd_path", type=click.Path(exists=True),
#               help='the CWD used for evaluate out-of-tree file access.')
def main(input_file, echo):
    cwd_path = os.path.abspath(os.path.dirname(input_file.name))

    trace_cntr = SyscallTraceConstructor(cwd_path)
    strace_str = input_file.read()

    trace_cntr.parse_strace_str(strace_str)
    file_usage = stat_file_usage(trace_cntr.syscalls, True)


if __name__ == '__main__':
    main()
