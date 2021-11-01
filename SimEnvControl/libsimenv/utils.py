import os
import hashlib
import shutil
import string
import sys

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


def is_valid_sha256(h):
    return len(h) == 64 and all(_ in string.hexdigits for _ in h)


def remove_path(p):
    # type: (str) -> (bool, str)
    if not os.path.exists(p):
        return True, "Success"
    if os.path.isfile(p):
        try:
            os.remove(p)
        except Exception as e:
            return False, str(e)
    else:
        try:
            shutil.rmtree(p)
        except Exception as e:
            return False, str(e)
    return True, "Success"


def fatal(s):
    print("Fatal: %s" % s, file=sys.stderr)
    sys.exit(-1)


def warning(s):
    print("Warning: %s" % s, file=sys.stderr)
