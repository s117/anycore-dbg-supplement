import os
from functools import partial
from typing import Callable, Iterable, Union, Dict

from click.core import Context, Argument, Option
from click.shell_completion import CompletionItem
from natsort import natsorted

from .checkpoints_db import get_available_checkpoints_for_app, get_all_available_checkpoints_for_any
from .manifest_db import get_avail_apps_in_db
from .repo_path import get_default_repo_path, get_sysroots_dir, get_manifests_dir, get_checkpoints_dir

from .sysroots_db import get_all_sysroots


def get_parsed_params(ctx):
    # type: (Context) -> Dict[str, str]
    parsed_params = dict()
    curr_ctx = ctx
    while curr_ctx:
        parsed_params = {**parsed_params, **curr_ctx.params}
        curr_ctx = curr_ctx.parent
    return parsed_params


def try_retrieve_value_from_envron(name):
    return os.environ.get(name, None)


def complete_sysroot_names(ctx, param, incomplete):
    # type: (Context, Union[Argument, Option], str) -> Iterable[Union[str,CompletionItem]]
    parsed_params = get_parsed_params(ctx)

    def try_get_sysroots_path():
        cmdline_val = parsed_params["repo_path"]
        envron_val = try_retrieve_value_from_envron("ATOOL_SIMENV_REPO_PATH")
        default_val = get_default_repo_path(False)
        if cmdline_val and os.path.isdir(get_sysroots_dir(cmdline_val)):
            return get_sysroots_dir(cmdline_val)
        elif envron_val and os.path.isdir(get_sysroots_dir(envron_val)):
            return get_sysroots_dir(envron_val)
        elif default_val and os.path.isdir(get_sysroots_dir(default_val)):
            return get_sysroots_dir(default_val)
        else:
            return None

    sysroots_path = try_get_sysroots_path()

    if not sysroots_path:
        return []

    sysroots = get_all_sysroots(sysroots_db_path=sysroots_path)
    return natsorted([sysroot for sysroot in sysroots if sysroot.startswith(incomplete)])


def complete_app_names(ctx, param, incomplete):
    # type: (Context, Union[Argument, Option], str) -> Iterable[Union[str,CompletionItem]]
    parsed_params = get_parsed_params(ctx)

    def try_get_manifest_db_path():
        cmdline_val = parsed_params["repo_path"]
        envron_val = try_retrieve_value_from_envron("ATOOL_SIMENV_REPO_PATH")
        default_val = get_default_repo_path(False)
        if cmdline_val and os.path.isdir(get_manifests_dir(cmdline_val)):
            return get_manifests_dir(cmdline_val)
        elif envron_val and os.path.isdir(get_manifests_dir(envron_val)):
            return get_manifests_dir(envron_val)
        elif default_val and os.path.isdir(get_manifests_dir(default_val)):
            return get_manifests_dir(default_val)
        else:
            return None

    manifest_db_path = try_get_manifest_db_path()

    if not manifest_db_path:
        return []
    apps = get_avail_apps_in_db(db_path=manifest_db_path)
    return natsorted([app for app in apps if app.startswith(incomplete)])


def complete_chkpt_names(ctx, param, incomplete):
    # type: (Context, Union[Argument, Option], str) -> Iterable[Union[str,CompletionItem]]
    parsed_params = get_parsed_params(ctx)
    if not parsed_params["app_name"] and len(ctx.args) == 1:
        parsed_params["app_name"] = ctx.args[0]

    def try_get_checkpoints_archive_path():
        cmdline_val = parsed_params["repo_path"]
        envron_val = try_retrieve_value_from_envron("ATOOL_SIMENV_REPO_PATH")
        default_val = ""
        if cmdline_val and os.path.isdir(get_checkpoints_dir(cmdline_val)):
            return get_checkpoints_dir(cmdline_val)
        elif envron_val and os.path.isdir(get_checkpoints_dir(envron_val)):
            return get_checkpoints_dir(envron_val)
        elif default_val and os.path.isdir(get_checkpoints_dir(default_val)):
            return get_checkpoints_dir(default_val)
        else:
            return None

    checkpoints_archive_path = try_get_checkpoints_archive_path()
    if not checkpoints_archive_path:
        return []
    if parsed_params["app_name"]:
        checkpoints = get_available_checkpoints_for_app(checkpoints_archive_path, parsed_params["app_name"])
    else:
        checkpoints = get_all_available_checkpoints_for_any(checkpoints_archive_path)

    return natsorted([chkpt for chkpt in checkpoints if chkpt.startswith(incomplete)])


def __no_filter(_):
    return True


def __complete_path(ctx, param, incomplete, file_filter):
    # type: (Context, Union[Argument, Option], str, Callable) -> Iterable[Union[str,CompletionItem]]
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
