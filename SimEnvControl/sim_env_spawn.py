#!/usr/bin/env python3
import os
import shutil
import sys
from typing import Dict

import click

from SyscallAnalysis.libsyscall.analyzer.check_scall import file_use_record
from .libsimenv.manifest_db import *
from .libsimenv.utils import sha256, get_pristine_spec_bench_run_dir


def prompt_run_name_suggestion(run_name):
    suggestions = get_run_name_suggestion(run_name, limit=10)
    if suggestions:
        print("Did you mean:", file=sys.stderr)
        for s in suggestions:
            print("\t%s" % s, file=sys.stderr)
    else:
        print("No run name suggestion.", file=sys.stderr)


def prompt_all_valid_run_name():
    all_available_run_names = sorted(get_avail_runs_in_db())
    if all_available_run_names:
        print("All valid run name", file=sys.stderr)
        for arn in all_available_run_names:
            print("\t%s" % arn, file=sys.stderr)
    else:
        print("No record in the manifest DB [%s]" % get_default_dbpath(), file=sys.stderr)
        print(
            "To generate manifest for a new benchmark, collect it's syscall trace then use the generate_manifest.py",
            file=sys.stderr

        )


def fatal(s):
    print("Fatal: %s" % s, file=sys.stderr)
    sys.exit(-1)


@click.command()
@click.argument("run-name", type=click.STRING)
@click.argument("new-dir", type=click.Path())
@click.option("-f", "--force", is_flag=True,
              help="If path [new-dir] already exist, remove it before creath new sim env")
@click.option("-a", "--print-all-valid-run-name", is_flag=True, help="Print all the available run name then exit")
@click.option("--spec-bench-dir", required=True, envvar='SPEC_BIN_DIR',
              type=click.Path(exists=True, dir_okay=True, file_okay=False),
              help='The path to the pristine compiled SPEC benchmark (produced by Speckle)')
def main(run_name, new_dir, force, print_all_valid_run_name, spec_bench_dir):
    if print_all_valid_run_name:
        prompt_all_valid_run_name()
        sys.exit(0)
    if os.path.exists(new_dir):
        if force:
            shutil.rmtree(new_dir)
        else:
            fatal("Path %s already exist, new sim env not spawn." % new_dir)
            sys.exit(-1)
    print("Spawning sim env for %s" % run_name)
    os.makedirs(new_dir, exist_ok=True)

    spec_bench_id = int(run_name.split(".")[0])
    if run_name.endswith("_ref"):
        spec_dataset = "ref"
    else:
        assert run_name.endswith("_test")
        spec_dataset = "test"
    pristine_spec_run_dir = get_pristine_spec_bench_run_dir(spec_bench_dir, spec_bench_id, spec_dataset)
    if not os.path.isdir(pristine_spec_run_dir):
        fatal("Pristine input dir [%s] does not exist, fail to spawn new sim env." % pristine_spec_run_dir)
        sys.exit(-1)

    try:
        manifest = load_from_manifest_db(run_name)
    except FileNotFoundError:
        fatal("Fatal: No manifest file for run '%s'" % run_name)
        prompt_run_name_suggestion(run_name)
        sys.exit(-1)

    os.chdir(new_dir)

    def spawn_symlink(src, dst):
        assert dst
        assert src
        par_dir = os.path.dirname(pname)
        spawn_dir(par_dir)
        if os.path.isdir(dst):
            fatal("Malformed manifest input: %s implies both input file and dir" % dst)
        os.symlink(src, dst)
        print("Symlink %s -> %s" % (src, dst))

    def spawn_dir(dpath):
        if dpath:
            if os.path.isfile(dpath):
                fatal("Malformed manifest input: %s implies both dir and input" % dpath)
            os.makedirs(dpath, exist_ok=True)
            print("mkdir %s" % dpath)

    for pname, details in manifest.items():
        # fuse_record = file_use_record.build_from_str(details['usage'])

        if details['spec_input']:
            pristine_spec_src_path = os.path.join(pristine_spec_run_dir, pname)

            if details['sha256']:
                if not os.path.isfile(pristine_spec_src_path):
                    fatal("Pristine SPEC input file [%s] doesn't exist" % pname)
                spawn_symlink(pristine_spec_src_path, pname)
            else:
                if not os.path.isdir(pristine_spec_src_path):
                    fatal("Pristine SPEC input dir [%s] doesn't exist" % pname)
                spawn_dir(pname)


if __name__ == '__main__':
    main()
