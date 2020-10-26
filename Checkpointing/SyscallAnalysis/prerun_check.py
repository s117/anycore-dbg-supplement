#!/usr/bin/env python3
import os
import sys
from typing import Dict, Set

import click

from libsyscall.analyzer.check_scall import file_use_record

SELF_PATH = os.path.dirname(os.path.abspath(__file__))
warning = list()
failures = list()


class CheckingFailure(RuntimeError):
    pass


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


def add_warning(warn):
    # type: (str) -> None
    warning.append(warn)
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


@click.command()
@click.argument("path", type=click.Path(exists=True))
def main(path):
    os.chdir(path)
    init_at_cwd = os.getcwd()
    bench_name = os.path.basename(init_at_cwd)
    print("Performing pre-run environment checking for run %s" % bench_name)

    from libsyscall.manifest_db import load_from_manifest_db
    manifest_db_dir = os.path.join(SELF_PATH, "manifest_db")
    manifest = load_from_manifest_db(manifest_db_dir, bench_name)

    spec_input_absref = list()
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
        print("Pre-Run checking passed.")


if __name__ == '__main__':
    main()
