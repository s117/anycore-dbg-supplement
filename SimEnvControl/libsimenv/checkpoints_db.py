import os
from typing import Dict, List


def get_app_ckpt_dir(ckpt_root, app_name):
    return os.path.join(ckpt_root, app_name)


def glob_all_checkpoints(chkpt_root):
    # type: (str) -> Dict[str, List[str]]
    apps = filter(lambda _p: os.path.isdir(get_app_ckpt_dir(chkpt_root, _p)), os.listdir(chkpt_root))

    def get_all_gz_in_dir(_dirpath):
        return list(filter(lambda _p: _p.endswith(".gz"), os.listdir(_dirpath)))

    result = dict()
    for app in apps:
        chkpts = get_all_gz_in_dir(get_app_ckpt_dir(chkpt_root, app))
        if chkpts:
            result[app] = chkpts

    return result


def get_available_checkpoints_for_app(chkpt_root, app):
    # type: (str, str) -> List[str]
    all_available = glob_all_checkpoints(chkpt_root)
    if app not in all_available:
        return []
    else:
        return all_available[app]


def get_all_available_checkpoints_for_any(chkpt_root):
    # type: (str) -> List[str]
    all_available = glob_all_checkpoints(chkpt_root)
    all_chkpts = []
    for v in all_available.values():
        all_chkpts.extend(v)
    return all_chkpts


def check_checkpoint_exist(chkpt_root, app_name, checkpoint):
    return os.path.isfile(
        get_checkpoint_abspath(chkpt_root, app_name, checkpoint)
    )


def get_checkpoint_abspath(chkpt_root, app_name, checkpoint):
    return os.path.join(
        get_app_ckpt_dir(chkpt_root, app_name), checkpoint
    )


if __name__ == '__main__':
    test_path = "/home/s117/sshfs_mnt/homelab_server/anycore-riscv/anycore-riscv-tests/build_gcc_chkpt/anycore-scratch/riscv_chkpts"


    def main():
        all_chkpt = glob_all_checkpoints(test_path)
        for app, chkpts in all_chkpt.items():
            print("- %s" % app)
            for chkpt in chkpts:
                print("   %s" % chkpt)


    main()
