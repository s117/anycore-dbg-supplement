#!/usr/bin/env python3
import os
import shutil
import sys

import click

from SimEnvControl.libsimenv.checkpoints_db import get_app_ckpt_dir, get_checkpoint_abspath
from SimEnvControl.libsimenv.repo_path import get_manifests_dir, get_checkpoints_dir
from .libsimenv.autocomplete import complete_app_names
from .libsimenv.manifest_db import is_app_available, prompt_app_name_suggestion
from .libsimenv.sysroots_db import set_file_readonly_ugo
from .libsimenv.utils import fatal, remove_path


@click.command()
@click.option("--repo-path", required=True,
              type=click.Path(exists=True, dir_okay=True, file_okay=False),
              help="The app repository path.")
@click.option("-s", "--scrub", is_flag=True,
              help="[Danger] Remove all existing checkpoint before importing any checkpoint.")
@click.argument("app-name", nargs=1, type=click.STRING, shell_complete=complete_app_names)
@click.argument("checkpoints", nargs=-1, type=click.Path(exists=False))
def addckpt(repo_path, app_name, checkpoints, scrub):
    """
    Import checkpoint.
    """
    manifest_db_path = get_manifests_dir(repo_path)
    checkpoints_archive_path = get_checkpoints_dir(repo_path)

    if not is_app_available(app_name, manifest_db_path):
        fatal("Manifest for app \"%s\" not found." % app_name)
        prompt_app_name_suggestion(app_name, manifest_db_path)
        sys.exit(-1)
    app_ckpt_dir = get_app_ckpt_dir(checkpoints_archive_path, app_name)

    if os.path.exists(app_ckpt_dir):
        if scrub:
            succ, msg = remove_path(app_ckpt_dir)
            if not succ:
                fatal("Fail to scrub existing checkpoint from \"%s\", reason:\n%s" % (app_ckpt_dir, msg))
        elif os.path.isfile(app_ckpt_dir):
            fatal("App's checkpoint dir is occupied by a file: %s" % app_ckpt_dir)

    os.makedirs(app_ckpt_dir, exist_ok=True)

    has_error = False
    for ckpt_src_path in checkpoints:
        if not os.path.isfile(ckpt_src_path):
            print("Checkpoint %s doesn't exist" % ckpt_src_path, file=sys.stderr)
            has_error = True
        if not ckpt_src_path.endswith(".gz"):
            print("Checkpoint %s doesn't have the .gz extension" % ckpt_src_path, file=sys.stderr)
            has_error = True
        ckpt_name = os.path.basename(ckpt_src_path)
        ckpt_dst_path = get_checkpoint_abspath(checkpoints_archive_path, app_name, ckpt_name)
        if os.path.exists(ckpt_dst_path):
            print("Checkpoint %s already exist in the repository." % ckpt_name, file=sys.stderr)
            has_error = True
    if has_error:
        sys.exit(-1)

    for ckpt_src_path in checkpoints:
        ckpt_name = os.path.basename(ckpt_src_path)
        ckpt_dst_path = get_checkpoint_abspath(checkpoints_archive_path, app_name, ckpt_name)
        print("Adding \"%s\"" % ckpt_dst_path)
        shutil.copy2(ckpt_src_path, ckpt_dst_path)
        set_file_readonly_ugo(ckpt_dst_path)

    print("Done.")


if __name__ == '__main__':
    addckpt()
