import os

import yaml

from fuzzywuzzy import fuzz


def save_to_manifest_db(db_path, record_name, manifest):
    out_filename = os.path.join(db_path, "%s.yaml" % record_name)
    with open(out_filename, "w") as out_fp:
        yaml.dump(manifest, out_fp)


def load_from_manifest_db(db_path, record_nane):
    in_filename = os.path.join(db_path, "%s.yaml" % record_nane)
    with open(in_filename, "r") as in_fp:
        return yaml.safe_load(in_fp)


def get_avail_runs_in_db(db_path):
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


def get_run_name_suggestion(db_path, name, limit):
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
