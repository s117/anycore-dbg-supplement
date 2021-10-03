#!/usr/bin/env python3
import pathlib
import click
import os
import shutil

from SimEnvControl.libsimenv.repo_path import create_repo
from .libsimenv.autocomplete import complete_path
from .libsimenv.sysroots_db import set_dir_readonly_ugo
from .libsimenv.utils import fatal, warning


@click.command()
@click.argument("new-repo-root", type=click.Path(exists=False), autocompletion=complete_path)
def init(new_repo_root):
    """
    Create an empty app repository.
    """
    if os.path.exists(new_repo_root):
        fatal("Path %s already exist." % new_repo_root)

    print("Creating empty app repo at \"%s\"" % new_repo_root)
    create_repo(new_repo_root)

    print("Done.")


if __name__ == '__main__':
    init()
