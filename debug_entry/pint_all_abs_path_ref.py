#!/usr/bin/env python3
import os
import shutil
import sys
from typing import Dict

import click

from SyscallAnalysis.libsyscall.analyzer.file_usage import FileUsageInfo
from SimEnvControl.libsimenv.manifest_db import *
from SimEnvControl.libsimenv.utils import sha256, get_pristine_spec_bench_run_dir


def main():
    all_available_run_names = sorted(get_avail_runs_in_db())
    for run_name in all_available_run_names:
        manifest = load_from_manifest_db(run_name)
        out_of_tree_refs = []
        for pname, details in manifest['fs_access'].items():
            fuse_record = FileUsageInfo.build_from_str(details['usage'])
            # if fuse_record.has_abs_ref() and os.path.isabs(pname):
            if fuse_record.has_abs_ref():
                out_of_tree_refs.append("  %s - %s" % (pname, details['usage']))
        if out_of_tree_refs:
            print("[%s]" % run_name)
            print("\n".join(out_of_tree_refs))


if __name__ == '__main__':
    main()
