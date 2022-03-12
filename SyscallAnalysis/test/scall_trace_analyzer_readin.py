import os

import click

from SyscallAnalysis.libsyscall.analyzer.syscall_trace_constructor import SyscallTraceConstructor


@click.command()
@click.argument("input_file", type=click.File())
def main(input_file):
    cwd_path = os.path.abspath(os.path.dirname(input_file.name))

    trace_cntr = SyscallTraceConstructor(cwd_path)
    strace_str = input_file.read()

    trace_cntr.parse_strace_str(strace_str)
    for t in trace_cntr.syscalls:
        print(str(t))


if __name__ == '__main__':
    main()
