#!/usr/bin/env python3
import click

from .sim_env_learn import learn as entry_learn
from .sim_env_spawn import spawn as entry_spawn
from .sim_env_verify import verify as entry_verify
from .sim_env_list import list as entry_list
from .sim_env_mkgen import mkgen as entry_mkgen

from .libsimenv.manifest_db import *


@click.group()
@click.pass_context
@click.option("--db-path", envvar='ATOOL_SIMENV_MANIFEST_DB_PATH',
              type=click.Path(exists=True, dir_okay=True, file_okay=False),
              help='Override the manifest directory path.')
@click.option("--checkpoints-archive-path", envvar='ATOOL_SIMENV_CHECKPOINTS_ARCHIVE_PATH',
              type=click.Path(exists=True, dir_okay=True, file_okay=False),
              help='Override the checkpoint archive directory path.')
def cli(ctx, db_path, checkpoints_archive_path):
    """
    The simenv utility
    """
    ctx.ensure_object(dict)
    if db_path:
        ctx.obj['manifest_db_path'] = db_path
    else:
        ctx.obj['manifest_db_path'] = get_default_dbpath()
    ctx.obj['checkpoints_archive_path'] = checkpoints_archive_path


cli.add_command(entry_spawn, name="spawn")
cli.add_command(entry_verify, name="verify")
cli.add_command(entry_list, name="list")
cli.add_command(entry_mkgen, name="mkgen")
cli.add_command(entry_learn, name="learn")
