#!/usr/bin/env python3
import pathlib
import click
import os
import shutil

from SyscallAnalysis.libsyscall.analyzer.file_usage import stat_file_usage
from SyscallAnalysis.libsyscall.analyzer.syscall_trace_constructor import SyscallTraceConstructor

from .libsimenv.autocomplete import complete_app_names, complete_dir, complete_path
from .libsimenv.manifest_db import save_to_manifest_db
from .libsimenv.sysroots_db import set_sysroot_dir_readonly
from .libsimenv.shcmd_utils import extract_stdin_file_from_shcmd
from .libsimenv.app_manifest import build_manifest
from .libsimenv.utils import fatal, warning


@click.command()
@click.pass_context
@click.argument("sysroot-name", autocompletion=complete_path)
@click.argument("sysroot-path", type=click.Path(exists=True, dir_okay=True, file_okay=False),
                autocompletion=complete_path)
def addsysroot(ctx, sysroot_name, sysroot_path):
    """
    Import a pristine sysroot for new app.
    """
    new_sysroot_path = os.path.join(ctx.obj['sysroots_archive_path'], sysroot_name)
    if os.path.isdir(new_sysroot_path):
        fatal("Sysroot name %s already exist." % sysroot_name)

    print("Importing pristine sysroot %s from \"%s\" to \"%s\"" % (sysroot_name, sysroot_path, new_sysroot_path))

    shutil.copytree(sysroot_path, new_sysroot_path, symlinks=False)
    set_sysroot_dir_readonly(new_sysroot_path)

    print("Done.")


if __name__ == '__main__':
    addsysroot()
