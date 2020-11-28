#!/usr/bin/env python3
import os
import shutil
import sys
from typing import Dict

import click

from .sim_env_learn import main as entry_learn
from .sim_env_spawn import main as entry_spawn
from .sim_env_verify import main as entry_verify
from .sim_env_show import main as entry_show
from .sim_env_mkgen import main as entry_mkgen

from .libsimenv.manifest_db import *


@click.group()
@click.pass_context
@click.option("--db-path", envvar='ATOOL_MANIFEST_DB_PATH',
              type=click.Path(exists=True, dir_okay=True, file_okay=False),
              help='Override the default manifest dir (%s)' % get_default_dbpath())
@click.option("--checkpoints-archive-path", envvar='ATOOL_CHECKPOINTS_ARCHIVE_PATH',
              type=click.Path(exists=True, dir_okay=True, file_okay=False),
              help='Where is the root to the checkpoints archive.')
def cli(ctx, db_path, checkpoints_archive_path):
    ctx.ensure_object(dict)
    if db_path:
        ctx.obj['manifest_db_path'] = db_path
    else:
        ctx.obj['manifest_db_path'] = get_default_dbpath()
    ctx.obj['checkpoints_archive_path'] = checkpoints_archive_path


cli.add_command(entry_learn, name="learn")
cli.add_command(entry_spawn, name="spawn")
cli.add_command(entry_verify, name="verify")
cli.add_command(entry_show, name="show")
cli.add_command(entry_mkgen, name="mkgen")
