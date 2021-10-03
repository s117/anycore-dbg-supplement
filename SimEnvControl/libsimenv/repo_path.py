import functools
import operator
import os
import sys
from pathlib import Path
from typing import Optional

_MANIFEST_DB_DIR = "manifests"
_CHECKPOINTS_DIR = "checkpoints"
_SYSROOTS_DIR = "sysroots"


def create_repo(path):
    # type: (str) -> None
    os.makedirs(path, exist_ok=True)
    os.makedirs(get_manifests_dir(path), exist_ok=True)
    os.makedirs(get_sysroots_dir(path), exist_ok=True)
    os.makedirs(get_checkpoints_dir(path), exist_ok=True)


def get_default_repo_path(create_if_not_exist):
    # type: (bool) -> Optional[str]
    default_dbpath = os.path.join(Path.home(), ".config", "simenv_repo")
    try:
        if not os.path.isdir(default_dbpath):
            if create_if_not_exist:
                create_repo(default_dbpath)
                return default_dbpath
            else:
                return None
    except FileExistsError as fe:
        raise RuntimeError(
            "Fail to create a default manifest DB directory at [%s]" % fe.filename
        )
    return default_dbpath


def get_manifests_dir(repo_path):
    # type: (Optional[str]) -> Optional[str]
    if not repo_path:
        return None
    return os.path.join(repo_path, _MANIFEST_DB_DIR)


def get_checkpoints_dir(repo_path):
    # type: (Optional[str]) -> Optional[str]
    if not repo_path:
        return None
    return os.path.join(repo_path, _CHECKPOINTS_DIR)


def get_sysroots_dir(repo_path):
    # type: (Optional[str]) -> Optional[str]
    if not repo_path:
        return None
    return os.path.join(repo_path, _SYSROOTS_DIR)


def check_repo(repo_path):
    # type: (Optional[str]) -> None

    path_to_check = (
        repo_path,
        get_sysroots_dir(repo_path),
        get_checkpoints_dir(repo_path),
        get_manifests_dir(repo_path)
    )
    path_status = tuple(map(os.path.isdir, path_to_check))

    if repo_path and functools.reduce(operator.and_, path_status):
        return
    print("Fatal: \"%s\" is not a valid simenv repository." % repo_path, file=sys.stderr)
    print("Repo status:", file=sys.stderr)
    for path, status in zip(path_to_check, path_status):
        print("  [%s]: %s" % (" Exist " if status else "Missing", path), file=sys.stderr)
    sys.exit(-1)
