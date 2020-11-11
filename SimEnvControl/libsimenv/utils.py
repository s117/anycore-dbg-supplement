import hashlib
import os

from .spec_bench_name import spec_bench_name


def sha256(fpath):
    # type: (str) -> str
    BUF_SIZE = 65536
    sha256 = hashlib.sha256()
    with open(fpath, 'rb') as f:
        while True:
            data = f.read(BUF_SIZE)
            if not data:
                break
            sha256.update(data)
    return sha256.hexdigest()


def get_pristine_spec_bench_run_dir(base, spec_no, dataset):
    # type: (str, int, str) -> str
    return os.path.join(
        base,
        "%s.%s_%s" % (spec_no, spec_bench_name[spec_no], dataset)
    )
