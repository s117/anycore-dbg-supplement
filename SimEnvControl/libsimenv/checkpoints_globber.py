import os


def glob_all_checkpoints(chkpt_root):
    apps = filter(lambda _p: os.path.isdir(os.path.join(chkpt_root, _p)), os.listdir(chkpt_root))

    def get_all_gz_in_dir(_dirpath):
        return tuple(filter(lambda _p: _p.endswith(".gz"), os.listdir(_dirpath)))

    result = dict()
    for app in apps:
        chkpts = get_all_gz_in_dir(os.path.join(chkpt_root, app))
        if chkpts:
            result[app] = chkpts

    return result


def check_checkpoint_exist(chkpt_root, app_name, checkpoint):
    return os.path.isfile(
        get_checkpoint_abspath(chkpt_root, app_name, checkpoint)
    )


def get_checkpoint_abspath(chkpt_root, app_name, checkpoint):
    return os.path.join(chkpt_root, app_name, checkpoint)


if __name__ == '__main__':
    test_path = "/home/s117/sshfs_mnt/homelab_server/anycore-riscv/anycore-riscv-tests/build_gcc_chkpt/anycore-scratch/riscv_chkpts"


    def main():
        all_chkpt = glob_all_checkpoints(test_path)
        for app, chkpts in all_chkpt.items():
            print("- %s" % app)
            for chkpt in chkpts:
                print("   %s" % chkpt)


    main()
