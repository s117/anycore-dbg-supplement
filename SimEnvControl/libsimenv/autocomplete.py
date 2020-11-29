import os
import sys
from functools import partial

from .manifest_db import get_avail_apps_in_db, get_default_dbpath
from .checkpoints_globber import get_all_available_checkpoints_for_any


def try_retrieve_option_value_from_args(args, option_name):
    option_found = False
    option_value = None

    for idx, arg in enumerate(args):
        if arg == option_name:
            option_found = True
            if idx + 1 < len(args):
                option_value = args[idx + 1]
            break
    return option_found, option_value


def try_retrieve_value_from_envron(name):
    return os.environ.get(name, None)


def complete_app_names(ctx, args, incomplete):
    def try_get_manifest_db_path():
        _, cmdline_val = try_retrieve_option_value_from_args(args, "--db-path")
        envron_val = try_retrieve_value_from_envron("ATOOL_SIMENV_MANIFEST_DB_PATH")
        default_val = get_default_dbpath()
        if cmdline_val and os.path.isdir(cmdline_val):
            return cmdline_val
        elif envron_val and os.path.isdir(envron_val):
            return envron_val
        elif default_val and os.path.isdir(default_val):
            return default_val
        else:
            return None

    manifest_db_path = try_get_manifest_db_path()

    if not manifest_db_path:
        return []
    apps = get_avail_apps_in_db(db_path=manifest_db_path)
    return [app for app in apps if app.startswith(incomplete)]


def complete_chkpt_names(ctx, args, incomplete):
    def try_get_checkpoints_archive_path():
        _, cmdline_val = try_retrieve_option_value_from_args(args, "--checkpoints-archive-path")
        envron_val = try_retrieve_value_from_envron("ATOOL_SIMENV_CHECKPOINTS_ARCHIVE_PATH")
        default_val = ""
        if cmdline_val and os.path.isdir(cmdline_val):
            return cmdline_val
        elif envron_val and os.path.isdir(envron_val):
            return envron_val
        elif default_val and os.path.isdir(default_val):
            return default_val
        else:
            return None

    checkpoints_archive_path = try_get_checkpoints_archive_path()
    if not checkpoints_archive_path:
        return []
    checkpoints = get_all_available_checkpoints_for_any(checkpoints_archive_path)
    return [chkpt for chkpt in checkpoints if chkpt.startswith(incomplete)]


def __no_filter(_):
    return True


def __complete_path(ctx, args, incomplete, file_filter):
    base_dir = os.path.dirname(incomplete)
    if base_dir:
        if not os.path.isdir(base_dir):
            return []
        options = filter(
            lambda _: file_filter(_) and _.startswith(incomplete),
            map(lambda _: os.path.join(base_dir, _), os.listdir(base_dir))
        )
    else:
        base_dir = "."
        options = filter(
            lambda _: file_filter(_) and _.startswith(incomplete),
            os.listdir(base_dir)
        )

    return options


complete_path = partial(__complete_path, file_filter=__no_filter)
complete_file = partial(__complete_path, file_filter=os.path.isfile)
complete_dir = partial(__complete_path, file_filter=os.path.isdir)
