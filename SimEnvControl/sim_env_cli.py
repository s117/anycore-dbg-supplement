#!/usr/bin/env python3
import click

from .sim_env_learn import learn as entry_learn
from .sim_env_spawn import spawn as entry_spawn
from .sim_env_verify import verify as entry_verify
from .sim_env_list import list as entry_list
from .sim_env_mkgen import mkgen as entry_mkgen
from .sim_env_addsysroot import addsysroot as entry_addsysroot
from .libsimenv.manifest_db import *
from .libsimenv.repo_path import *


@click.group()
@click.pass_context
@click.option("--repo-path", envvar='ATOOL_SIMENV_REPO_PATH',
              type=click.Path(exists=True, dir_okay=True, file_okay=False),
              help='Override the SimEnv repository path given by the environmental variable "ATOOL_SIMENV_REPO_PATH".')
def cli(ctx, repo_path):
    """
    The simenv utility
    """
    ctx.ensure_object(dict)
    if not repo_path:
        repo_path = get_default_repo_path(True)
    check_repo(repo_path)
    ctx.obj['manifest_db_path'] = get_manifest_dir(repo_path)
    ctx.obj['checkpoints_archive_path'] = get_chkpt_dir(repo_path)
    ctx.obj['sysroots_archive_path'] = get_sysroots_dir(repo_path)


cli.add_command(entry_spawn, name="spawn")
cli.add_command(entry_verify, name="verify")
cli.add_command(entry_list, name="list")
cli.add_command(entry_mkgen, name="mkgen")
cli.add_command(entry_learn, name="learn")
cli.add_command(entry_addsysroot, name="addsysroot")
