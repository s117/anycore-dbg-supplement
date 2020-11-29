import os
import sys
from collections import defaultdict
from typing import List

import yaml

from fuzzywuzzy import fuzz
from pathlib import Path

from .checkpoints_globber import glob_all_checkpoints


def get_default_dbpath():
    default_dbpath = os.path.join(Path.home(), ".config", "atool", "app_manifests")
    try:
        if not os.path.isdir(default_dbpath):
            os.makedirs(default_dbpath, exist_ok=True)
    except FileExistsError as fe:
        raise RuntimeError(
            "Fail to create the default manifest DB directory at [%s]" % fe.filename
        )
    return default_dbpath


def save_to_manifest_db(record_name, manifest, db_path=get_default_dbpath()):
    out_filename = os.path.join(db_path, "%s.yaml" % record_name)
    with open(out_filename, "w") as out_fp:
        yaml.dump(manifest, out_fp)


def load_from_manifest_db(record_name, db_path=get_default_dbpath()):
    in_filename = os.path.join(db_path, "%s.yaml" % record_name)
    with open(in_filename, "r") as in_fp:
        return yaml.safe_load(in_fp)


def get_avail_apps_in_db(db_path=get_default_dbpath()):
    # type: (str) -> List[str]
    try:
        avail_apps = list(map(
            lambda tp: tp[0],
            filter(
                lambda tp: tp[1].lower() == ".yaml",
                map(
                    lambda p: os.path.splitext(p),
                    os.listdir(db_path)
                )
            )
        ))
    except FileNotFoundError:
        return []

    return avail_apps


def get_app_name_suggestion(name, limit, db_path=get_default_dbpath()):
    PICKING_FUZZ_RATION_THRESHOLD = 70
    avail_apps = get_avail_apps_in_db(db_path)
    ranked_suggestions = sorted(map(
        lambda arn: (arn, fuzz.ratio(name, arn)),
        avail_apps
    ), key=lambda i: i[1], reverse=True)
    suggestion_list = list()
    for r_idx in range(min(len(ranked_suggestions), limit)):
        if ranked_suggestions[r_idx][1] >= PICKING_FUZZ_RATION_THRESHOLD:
            suggestion_list.append(ranked_suggestions[r_idx][0])

    return suggestion_list


def is_app_available(name, db_path=get_default_dbpath()):
    return os.path.isfile(os.path.join(db_path, "%s.yaml" % name))


def prompt_app_name_suggestion(app_name, db_path):
    suggestions = get_app_name_suggestion(app_name, limit=10, db_path=db_path)
    if suggestions:
        print("Did you mean:", file=sys.stderr)
        for s in suggestions:
            print("\t%s" % s, file=sys.stderr)
    else:
        print("No app name suggestion.", file=sys.stderr)


def prompt_all_valid_app_name(db_path, checkpoints_archive_path):
    if checkpoints_archive_path:
        apps_chkpts = defaultdict(tuple, glob_all_checkpoints(checkpoints_archive_path))
    else:
        apps_chkpts = defaultdict(tuple)

    all_available_app_names = sorted(get_avail_apps_in_db(db_path))
    if all_available_app_names:
        print("All available app:", file=sys.stderr)
        for arn in all_available_app_names:
            if checkpoints_archive_path:
                n_chkpts = len(apps_chkpts[arn])
                print("\t%s (%d %s available)" % (arn, n_chkpts, "checkpoints" if n_chkpts > 1 else "checkpoint"),
                      file=sys.stderr)
            else:
                print("\t%s" % arn, file=sys.stderr)
    else:
        print("No record in the manifest DB [%s]" % get_default_dbpath(), file=sys.stderr)
        print(
            "To generate manifest for a new benchmark, collect it's syscall trace then use the generate_manifest.py",
            file=sys.stderr
        )
