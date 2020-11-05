#!/usr/bin/env python3
import os
from typing import Dict, Set

import click

from libsyscall.analyzer.check_scall import check_file_usage, check_out_of_tree_reference, check_abs_path_reference, \
    path_whitelist, file_use_record
from libsyscall.analyzer.scall_trace_analyzer import scall_trace_analyzer
from libsyscall.spec_bench_name import spec_bench_name

SPEC_BENCH_DIR = "/home/s117/SPX_Garage/AnyCore/spec/compile/Speckle/built_bin/riscv64-unknown-linux-gnu-gcc-9.2.0/any"


def get_pristine_spec_bench_run_dir(base, spec_no, dataset):
    # type: (str, int, str) -> str
    return os.path.join(
        base,
        "%s.%s_%s" % (spec_no, spec_bench_name[spec_no], dataset)
    )


def sha256(fpath):
    # type: (str) -> str
    import hashlib
    BUF_SIZE = 65536
    sha256 = hashlib.sha256()
    with open(fpath, 'rb') as f:
        while True:
            data = f.read(BUF_SIZE)
            if not data:
                break
            sha256.update(data)
    return sha256.hexdigest()


def build_manifest(tree_root, file_usage_info):
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
    #   if exist in SPEC input:
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
            in_tree_path_abs = os.path.join(tree_root, pname)
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
@click.argument("input_file", type=click.File())
@click.option('--echo', is_flag=True, help='echo the decoded scall trace.')
def main(input_file, echo):
    init_at_cwd = os.path.abspath(os.path.dirname(input_file.name))
    bench_name = os.path.basename(init_at_cwd)

    print("Generating manifest for run %s" % bench_name)

    spec_bench_id = int(bench_name.split(".")[0])
    if bench_name.endswith("_ref"):
        spec_dataset = "ref"
    else:
        assert bench_name.endswith("_test")
        spec_dataset = "test"
    pristine_spec_run_dir = get_pristine_spec_bench_run_dir(SPEC_BENCH_DIR, spec_bench_id, spec_dataset)

    trace_analyzer = scall_trace_analyzer(init_at_cwd)
    strace_str = input_file.read()
    trace_analyzer.parse_strace_str(strace_str)

    if echo:
        for t in trace_analyzer.syscalls:
            print(str(t))

    file_usage_info = check_file_usage(trace_analyzer, init_at_cwd)
    manifest = build_manifest(pristine_spec_run_dir, file_usage_info)

    from libsyscall.manifest_db import save_to_manifest_db
    save_to_manifest_db(bench_name, manifest)


if __name__ == '__main__':
    main()
