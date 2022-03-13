#!/usr/bin/env python3

import click

from .app_repo_addckpt import addckpt as entry_addckpt
from .app_repo_addsysroot import addsysroot as entry_addsysroot
from .app_repo_init import init as entry_init
from .app_repo_learn import learn as entry_learn
from .app_repo_subrepo import subrepo as entry_subrepo

# To support auto-completion in bash 4.2 shipped with CentOS 7
from .libsimenv.click_bash42_completion import patch
patch()

@click.group()
def cli():
    """
    The app repository management utility
    """
    pass


cli.add_command(entry_init, name="init")
cli.add_command(entry_addsysroot, name="addsysroot")
cli.add_command(entry_learn, name="learn")
cli.add_command(entry_addckpt, name="addckpt")
cli.add_command(entry_subrepo, name="subrepo")
