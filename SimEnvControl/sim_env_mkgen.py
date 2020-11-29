#!/usr/bin/env python3
import click

from .libsimenv.autocomplete import complete_chkpt_names, complete_app_names
from .libsimenv.app_manifest import *
from .libsimenv.checkpoints_globber import *
from .libsimenv.makefile_generator.makefile_generator import *
from .libsimenv.manifest_db import *

from .libsimenv.utils import *


@click.command()
@click.pass_context
@click.argument("app-name", autocompletion=complete_app_names, type=click.STRING)
@click.option("-f", "--checkpoint", autocompletion=complete_chkpt_names,
              help="If give and exist, the generated makefile will load the given checkpoint by default.")
def mkgen(ctx, app_name, checkpoint):
    """
    Generate a Makefile for a simenv, at current dir.
    """
    manifest_db_path = ctx.obj['manifest_db_path']
    checkpoints_archive_path = ctx.obj['checkpoints_archive_path']
    if checkpoint and not checkpoints_archive_path:
        fatal("Checkpoints archive root must be provided if you want to load a checkpoint.")

    try:
        manifest = load_from_manifest_db(app_name)
        verify_manifest_format(manifest)
        if checkpoint and not check_checkpoint_exist(checkpoints_archive_path, app_name, checkpoint):
            fatal("App %s doesn't have checkpoint %s" % (app_name, checkpoint))
    except FileNotFoundError:
        print("Fatal: No manifest file for app '%s'" % app_name, file=sys.stderr)
        prompt_app_name_suggestion(app_name, manifest_db_path)
        sys.exit(-1)
    except ValueError as ve:
        fatal("%s has a malformed manifest (%s)" % (app_name, ve))
    else:
        print(
            "Generating makefile simenv for app %s%s" % (
                app_name, ", checkpoint %s" % checkpoint if checkpoint else "")
        )
        app_name = manifest["app_name"]
        app_cmd = manifest["app_cmd"]
        app_init_cwd = manifest["app_init_cwd"]
        app_memsize = manifest["app_memsize"]
        if checkpoint:
            sim_flags = "-f%s" % get_checkpoint_abspath(checkpoints_archive_path, app_name, checkpoint)
        else:
            sim_flags = ""
        generated_makefile = generate_makefile(
            app_name=app_name,
            app_cmd=app_cmd,
            app_init_cwd=app_init_cwd,
            app_memsize=app_memsize,
            sim_cmd="spike",
            sim_flags=sim_flags,
            fesvr_flags="",
            pk_flags="-c"
        )
        with open("Makefile", "w") as fp:
            fp.write(generated_makefile)


if __name__ == '__main__':
    mkgen()
