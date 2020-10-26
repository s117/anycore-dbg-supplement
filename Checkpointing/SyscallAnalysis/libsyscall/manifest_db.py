import os

import yaml


def save_to_manifest_db(db_path, record_name, manifest):
    out_filename = os.path.join(db_path, "%s.yaml" % record_name)
    with open(out_filename, "w") as out_fp:
        yaml.dump(manifest, out_fp)


def load_from_manifest_db(db_path, record_nane):
    in_filename = os.path.join(db_path, "%s.yaml" % record_nane)
    with open(in_filename, "r") as in_fp:
        return yaml.safe_load(in_fp)
