#!/usr/bin/env python3
import os
import sys
from typing import Dict

import click

from SyscallAnalysis.libsyscall.analyzer.check_scall import check_file_usage, path_whitelist, file_use_record
from SyscallAnalysis.libsyscall.analyzer.scall_trace_analyzer import scall_trace_analyzer
from .libsimenv.manifest_db import save_to_manifest_db
from .libsimenv.utils import sha256, get_pristine_spec_bench_run_dir


def build_manifest(pristine_tree_root, file_usage_info):
    # type: (str, Dict[str, file_use_record]) -> Dict
    # in (rd/wt/rw)_files, only the files that are out of the tree_root are represented in abspath
    manifest = dict()

    def create_manifest_entry(path, file_usage, is_spec_input):
        # type: (str, file_use_record, bool) -> Dict
        is_dir = os.path.isdir(path)
        if is_spec_input and not is_dir:
            sha256_hash = sha256(path)
        else:
            sha256_hash = None
        return {
            "spec_input": is_spec_input,
            "usage": str(file_usage),
            "sha256": sha256_hash
        }

    # OoT access:
    #   if not whitelisted:
    #     error # only allow whitelisted OoT access
    #   if FUSE_WRITE or FUSE_REMOVE or FUSE_CREATE:
    #     error # no OoT modification allowed
    #   create_entry
    #
    # InT access:
    #   if exist in pristine input:
    #     if FUSE_WRITE or FUSE_REMOVE:
    #       fatal # input modification not allowed
    #     create_entry with SHA256
    #   else:
    #     if FUSE_READ and no FUSE_CREATE:
    #       error # read not existed file, should never happens if everything is good
    #     create_entry
    for pname, use_info in file_usage_info.items():
        if os.path.isabs(pname):  # OoT (Out of Tree) access
            if pname not in path_whitelist:
                raise RuntimeError("Only whitelisted Out of Tree access is allowed: \"%s\" - %s" % (pname, use_info))
            if use_info.has_write_data() or use_info.has_remove() or use_info.has_create():
                raise RuntimeError("Detected Out of Tree modification: \"%s\" - %s" % (pname, use_info))
            entry = create_manifest_entry(pname, use_info, is_spec_input=False)
        else:  # InT (In Tree) access
            in_tree_path_abs = os.path.join(pristine_tree_root, pname)
            if os.path.exists(in_tree_path_abs):
                if use_info.has_write_data() or use_info.has_remove():
                    raise RuntimeError("Detected modification on SPEC input file: \"%s\" - %s" % (pname, use_info))
                entry = create_manifest_entry(in_tree_path_abs, use_info, is_spec_input=True)
            else:
                if use_info.has_read_data() and not use_info.has_create():
                    raise RuntimeError(
                        "Trying to read a not existed file \"%s\" - %s\n"
                        " (this exception should not happen if everything is good)" % (pname, use_info)
                    )
                entry = create_manifest_entry(pname, use_info, is_spec_input=False)
        manifest[pname] = entry

    return manifest


@click.command()
@click.argument('input-file', type=click.File())
@click.option('--echo', is_flag=True, help='echo the decoded scall trace.')
@click.option("-n", "--run-name", help="Override the run name (default is the name of folder where input is located)")
@click.option("--spec-bench-dir", required=True, envvar='SPEC_BIN_DIR',
              type=click.Path(exists=True, dir_okay=True, file_okay=False),
              help='The path to the pristine compiled SPEC benchmark (produced by Speckle)')
def main(input_file, echo, run_name, spec_bench_dir):
    init_at_cwd = os.path.abspath(os.path.dirname(input_file.name))
    if not run_name:
        run_name = os.path.basename(init_at_cwd)

    print("Generating manifest for run %s" % run_name)

    spec_bench_id = int(run_name.split(".")[0])
    if run_name.endswith("_ref"):
        spec_dataset = "ref"
    else:
        assert run_name.endswith("_test")
        spec_dataset = "test"
    pristine_spec_run_dir = get_pristine_spec_bench_run_dir(spec_bench_dir, spec_bench_id, spec_dataset)
    if not os.path.isdir(pristine_spec_run_dir):
        print("Pristine input dir [%s] does not exist, cannot analysis the syscall" % pristine_spec_run_dir,
              file=sys.stderr)
        sys.exit(-1)

    trace_analyzer = scall_trace_analyzer(init_at_cwd)
    strace_str = input_file.read()
    trace_analyzer.parse_strace_str(strace_str)

    if echo:
        for t in trace_analyzer.syscalls:
            print(str(t))

    file_usage_info = check_file_usage(trace_analyzer, init_at_cwd)
    manifest = build_manifest(pristine_spec_run_dir, file_usage_info)

    save_to_manifest_db(run_name, manifest)


if __name__ == '__main__':
    main()
