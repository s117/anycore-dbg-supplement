import os
import stat
from typing import Dict, List


def get_pristine_sysroot_dir(sysroots_db_path, sysroot_name):
    return os.path.join(sysroots_db_path, sysroot_name)


def is_sysroot_available(sysroots_db_path, sysroot_name):
    return os.path.isdir(
        get_pristine_sysroot_dir(sysroots_db_path, sysroot_name)
    )


def get_all_sysroots(sysroots_db_path):
    # type: (str) -> List[str]
    sysroots = list(filter(lambda _p: is_sysroot_available(sysroots_db_path, _p), os.listdir(sysroots_db_path)))

    return sysroots


def set_file_readonly_ugo(filepath):
    no_write_mask = ~(stat.S_IWUSR | stat.S_IWGRP | stat.S_IWOTH)
    mode = os.stat(filepath).st_mode
    os.chmod(filepath, mode=mode & no_write_mask)


def set_file_writable_u(filepath):
    mode = os.stat(filepath).st_mode
    os.chmod(filepath, mode=mode | stat.S_IWUSR)


def set_dir_readonly_ugo(path):
    # type: (str) -> None
    no_write_mask = ~(stat.S_IWUSR | stat.S_IWGRP | stat.S_IWOTH)
    for root, dirs, files in os.walk(path):
        for dname in dirs:
            set_file_readonly_ugo(os.path.join(root, dname))
        for fname in files:
            set_file_readonly_ugo(os.path.join(root, fname))
    set_file_readonly_ugo(path)


def set_dir_writeable_u(path):
    # type: (str) -> None
    for root, dirs, files in os.walk(path):
        for dname in dirs:
            set_file_writable_u(os.path.join(root, dname))
        for fname in files:
            set_file_writable_u(os.path.join(root, fname))
    set_file_writable_u(path)


if __name__ == '__main__':
    test_path = "/home/s117/sshfs_mnt/homelab_server/anycore-riscv/anycore-riscv-tests/build_gcc_chkpt/anycore-scratch/riscv_chkpts"


    def main():
        sysroots = get_all_sysroots(test_path)
        for sysroot in sysroots:
            print("%s" % sysroot)


    main()
