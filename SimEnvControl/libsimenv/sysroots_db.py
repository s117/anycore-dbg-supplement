import os
import stat
from typing import Dict, List


def get_all_sysroots(sysroots_root):
    # type: (str) -> List[str]
    sysroots = list(filter(lambda _p: os.path.isdir(os.path.join(sysroots_root, _p)), os.listdir(sysroots_root)))

    return sysroots


def set_sysroot_dir_readonly(path):
    # type: (str) -> None
    no_write_mask = ~(stat.S_IWUSR | stat.S_IWGRP | stat.S_IWOTH)
    for root, dirs, files in os.walk(path):
        for dname in dirs:
            dpath = os.path.join(root, dname)
            mode = os.stat(dpath).st_mode
            os.chmod(dpath, mode=mode & no_write_mask)
        for fname in files:
            fpath = os.path.join(root, fname)
            mode = os.stat(fpath).st_mode
            os.chmod(fpath, mode=mode & no_write_mask)
    mode = os.stat(path).st_mode
    os.chmod(path, mode=mode & no_write_mask)


def set_sysroot_dir_writeable(path):
    # type: (str) -> None
    for root, dirs, files in os.walk(path):
        for dname in dirs:
            dpath = os.path.join(root, dname)
            mode = os.stat(dpath).st_mode
            os.chmod(dpath, mode=mode | stat.S_IWUSR)
        for fname in files:
            fpath = os.path.join(root, fname)
            mode = os.stat(fpath).st_mode
            os.chmod(fpath, mode=mode | stat.S_IWUSR)
    mode = os.stat(path).st_mode
    os.chmod(path, mode=mode | stat.S_IWUSR)


if __name__ == '__main__':
    test_path = "/home/s117/sshfs_mnt/homelab_server/anycore-riscv/anycore-riscv-tests/build_gcc_chkpt/anycore-scratch/riscv_chkpts"


    def main():
        sysroots = get_all_sysroots(test_path)
        for sysroot in sysroots:
            print("%s" % sysroot)


    main()
