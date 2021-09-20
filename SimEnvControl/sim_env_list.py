#!/usr/bin/env python3
import click

from .libsimenv.autocomplete import complete_app_names
from .libsimenv.manifest_db import *
from .libsimenv.utils import *
from .libsimenv.checkpoints_db import glob_all_checkpoints


@click.command()
@click.pass_context
@click.argument("app-names", type=click.STRING, nargs=-1, autocompletion=complete_app_names)
def list(ctx, app_names):
    """
    List available apps and checkpoints in the SimEnv repository.
    """
    manifest_db_path = ctx.obj['manifest_db_path']
    checkpoints_archive_path = ctx.obj['checkpoints_archive_path']
    if not app_names:
        prompt_all_valid_app_name(manifest_db_path, checkpoints_archive_path)
        if not checkpoints_archive_path:
            print("No checkpoint information available because the repository root is not set.")
            print(
                "Specify it using --repo-path or environment variable 'ATOOL_SIMENV_REPO_PATH'."
            )
        else:
            print(
                "Run `%s list [app names]` to see the name of available checkpoint(s)." % os.path.basename(sys.argv[0]))
    else:
        if not checkpoints_archive_path:
            fatal("You must provide the path to the checkpoint archive to see which checkpoints are available.")
        apps_chkpts = defaultdict(tuple, glob_all_checkpoints(checkpoints_archive_path))
        for app in app_names:
            if not is_app_available(app, manifest_db_path):
                print("App %s doesn't exist." % app)
                prompt_app_name_suggestion(app, manifest_db_path)
                exit(-1)
        for app in app_names:
            app_chkpts = apps_chkpts[app]
            if app_chkpts:
                print("Available checkpoints for app %s:" % app)
                for app_chkpt in app_chkpts:
                    print("   %s" % app_chkpt)
                print()
            else:
                print("No checkpoint available for this app.")
                print()


if __name__ == '__main__':
    list()
