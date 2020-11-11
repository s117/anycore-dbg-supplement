import os

import yaml

from fuzzywuzzy import fuzz
from pathlib import Path


def get_default_dbpath():
    default_dbpath = os.path.join(Path.home(), ".config", "anycore-dbg-supplement", "spec_bench_manifest_db")
    try:
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


def get_avail_runs_in_db(db_path=get_default_dbpath()):
    avail_runs = list(map(
        lambda tp: tp[0],
        filter(
            lambda tp: tp[1].lower() == ".yaml",
            map(
                lambda p: os.path.splitext(p),
                os.listdir(db_path)
            )
        )
    ))

    return avail_runs


def get_run_name_suggestion(name, limit, db_path=get_default_dbpath()):
    PICKING_FUZZ_RATION_THRESHOLD = 70
    avail_runs = get_avail_runs_in_db(db_path)
    ranked_suggestions = sorted(map(
        lambda arn: (arn, fuzz.ratio(name, arn)),
        avail_runs
    ), key=lambda i: i[1], reverse=True)
    suggestion_list = list()
    for r_idx in range(min(len(ranked_suggestions), limit)):
        if ranked_suggestions[r_idx][1] >= PICKING_FUZZ_RATION_THRESHOLD:
            suggestion_list.append(ranked_suggestions[r_idx][0])

    return suggestion_list
