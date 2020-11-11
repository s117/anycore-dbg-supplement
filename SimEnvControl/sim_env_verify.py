#!/usr/bin/env python3
import os
import sys
from typing import Dict

import click

from SyscallAnalysis.libsyscall.analyzer.check_scall import file_use_record
from .libsimenv.manifest_db import *
from .libsimenv.utils import sha256

warnings = list()
failures = list()


class CheckingFailure(RuntimeError):
    pass


def add_warning(warn):
    # type: (str) -> None
    warnings.append(warn)
    print("Warning: %s" % warn, file=sys.stderr)


def add_failure(fail):
    # type: (str) -> None
    failures.append(fail)


def check_read(pname):
    return os.access(pname, os.R_OK)


def check_dir_writeable(dirname):
    if os.path.isdir(dirname):
        return os.access(dirname, os.W_OK)
    pdir = os.path.dirname(dirname)
    if not pdir: pdir = '.'
    return check_dir_writeable(pdir)


def check_write(pname):
    if os.path.exists(pname):
        if os.path.isfile(pname):
            return os.access(pname, os.W_OK)
        else:
            return False
    return check_dir_writeable(pname)


def check_stat(pname):
    return os.path.exists(pname)


def check_spec_input(name, details, fuse_record):  # type: (str, Dict, file_use_record) -> bool
    print("Checking SPEC input file \"%s\"" % name)
    if fuse_record.has_abs_ref():
        add_warning("SPEC input will be referenced by absolute path - \"%s\"" % name)
    if not os.path.exists(name):
        add_failure("Required SPEC input file/dir doesn't exist in CWD - \"%s\"" % name)
        return False
    expected_sha256 = details['sha256']
    if expected_sha256:
        try:
            actual_sha256 = sha256(name)
        except FileNotFoundError:
            add_failure("Fail to get the SHA256 hash of file in CWD - \"%s\"" % name)
            return False
        if actual_sha256 != expected_sha256:
            add_failure("SPEC input file's HASH doesn't match - \"%s\"" % name)
            return False
    return True


def check_non_spec_input(name, details, fuse_record):  # type: (str, Dict, file_use_record) -> bool
    print("Checking Non-SPEC input file \"%s\" (no integrity checking)" % name)
    if fuse_record.has_abs_ref():
        add_warning("Non-SPEC input file will be referenced by absolute path - \"%s\"" % name)

    if not os.path.exists(name):
        add_failure("Non-SPEC input file doesn't exist - \"%s\"" % name)
        return False

    if fuse_record.has_read_data():
        if not check_read(name):
            add_failure("Cannot read Non-SPEC input file - \"%s\"" % name)
            return False

    return True


def check_output(name, details, fuse_record):  # type: (str, Dict, file_use_record) -> bool
    print("Checking output permission \"%s\"" % name)
    if fuse_record.has_abs_ref():
        add_warning("Output will be referenced by absolute path - \"%s\"" % name)
    if not check_write(name):
        add_failure("No write permission on output file - \"%s\"" % name)
        return False
    return True


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


@click.command()
@click.argument("sim_dir", type=click.Path(exists=True, dir_okay=True, file_okay=False))
@click.option("-n", "--run-name", help="Override the run name (default is the folder name)")
@click.option("-a", "--print-all-valid-run-name", is_flag=True, help="Print all the available run name then exit")
def main(sim_dir, run_name, print_all_valid_run_name):
    if print_all_valid_run_name:
        prompt_all_valid_run_name()
        sys.exit(0)

    os.chdir(sim_dir)
    init_at_cwd = os.getcwd()
    if not run_name:
        run_name = os.path.basename(init_at_cwd)
    print("Start file environment pre-run checking: '%s' at '%s'\n" % (run_name, sim_dir))

    try:
        manifest = load_from_manifest_db(run_name)
    except FileNotFoundError:
        print("Fatal: No manifest file for run '%s'" % run_name, file=sys.stderr)
        prompt_run_name_suggestion(run_name)
        sys.exit(-1)

    check_succ = True
    for pname, details in manifest.items():
        fuse_record = file_use_record.build_from_str(details['usage'])
        if details['spec_input']:
            check_succ &= check_spec_input(pname, details, fuse_record)
        else:
            if not fuse_record.has_write_data() and not fuse_record.has_remove() and (
                    fuse_record.has_stat() or fuse_record.has_read_data() or fuse_record.has_open()
            ):
                check_succ &= check_non_spec_input(pname, details, fuse_record)
            elif fuse_record.has_write_data() or fuse_record.has_remove() or fuse_record.has_create():
                check_succ &= check_output(pname, details, fuse_record)
    print()
    if failures:
        print("Pre-Run checking failed:")
        for f in failures:
            print(f, file=sys.stderr)
        sys.exit(-1)
    else:
        print("Pre-Run checking passed%s." % (" with warning" if warnings else ""))


if __name__ == '__main__':
    main()
