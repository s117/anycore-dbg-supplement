#!/usr/bin/env python3
import shutil

import click

from SimEnvControl.libsimenv.repo_path import get_sysroots_dir
from .libsimenv.sysroots_db import *
from .libsimenv.utils import fatal, remove_path


@click.command()
@click.option("--repo-path", required=True, type=click.Path(exists=True, dir_okay=True, file_okay=False),
              help="The app repository path.")
@click.option("-s", "--scrub", is_flag=True,
              help="[Danger] Remove existing sysroot from the repository before importing the new sysroot.")
@click.argument("sysroot-name")
@click.argument("sysroot-path", type=click.Path(exists=True, dir_okay=True, file_okay=False))
def addsysroot(repo_path, sysroot_name, sysroot_path, scrub):
    """
    Import a pristine sysroot.
    """
    sysroots_archive_path = get_sysroots_dir(repo_path)

    new_sysroot_path = get_pristine_sysroot_dir(sysroots_archive_path, sysroot_name)
    if os.path.exists(new_sysroot_path):
        if scrub:
            set_dir_writeable_u(new_sysroot_path)
            succ, msg = remove_path(new_sysroot_path)
            if not succ:
                fatal("Fail to remove existed sysroot at \"%s\", reason:\n%s" % (new_sysroot_path, msg))
        elif os.path.isdir(new_sysroot_path):
            fatal("Sysroot name %s already exist." % sysroot_name)
        elif os.path.isfile(new_sysroot_path):
            fatal("The place for the new sysroot is occupied by a file: \"%s\"" % sysroot_name)

    print("Importing pristine sysroot %s from \"%s\" to \"%s\"" % (sysroot_name, sysroot_path, new_sysroot_path))

    shutil.copytree(sysroot_path, new_sysroot_path, symlinks=False)
    set_dir_readonly_ugo(new_sysroot_path)

    print("Done.")


if __name__ == '__main__':
    addsysroot()
