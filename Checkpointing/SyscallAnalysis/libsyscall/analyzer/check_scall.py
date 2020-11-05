#!/usr/bin/env python3
import os
from collections import defaultdict
from typing import Dict

import click
from ..syscalls import syscall as s
from .scall_trace_analyzer import scall_trace_analyzer

path_whitelist = {
    "/etc/localtime",
    "/bin/pwd",
    "/usr/include",
    "/dev/urandom"
}


def check_abs_path_reference(analyzer, print_info=False):
    # type: (scall_trace_analyzer, bool) -> bool
    interested_scalls = list()
    interested_paths = set()

    for scall in analyzer.syscalls:
        if isinstance(scall, s.mixin_syscall_has_path_args):
            has_abspath = False
            for path_ref in scall.get_arg_paths():
                if path_ref.isabs() and path_ref.abspath() not in path_whitelist:
                    has_abspath = True
                    interested_paths.add(path_ref)
            if has_abspath:
                interested_scalls.append(scall)
    if interested_paths:
        if print_info:
            print("Warning: the following syscalls have absolute path reference:")
            for scall in interested_scalls:
                print(str(scall))
            print("Paths being referenced")
            for path in interested_paths:
                print(path.rawpath())
        return False
    return True


def check_out_of_tree_reference(analyzer, tree_root, print_info=False):
    # type: (scall_trace_analyzer, str, bool) -> bool
    interested_scalls = list()
    interested_paths = set()
    assert os.path.isabs(tree_root)
    tree_root = s.path("", tree_root)

    for scall in analyzer.syscalls:
        if isinstance(scall, s.mixin_syscall_has_path_args):
            has_oot = False
            for path_ref in scall.get_arg_paths():
                if not tree_root.contains(path_ref) and path_ref.abspath() not in path_whitelist:
                    has_oot = True
                    interested_paths.add(path_ref)
            if has_oot:
                interested_scalls.append(scall)

    if interested_paths:
        if print_info:
            print("Warning: the following syscalls have unidentified out of tree reference:")
            for scall in interested_scalls:
                print(str(scall))
            print("Paths being referenced")
            for path in interested_paths:
                if path.isabs():
                    print(path.rawpath())
                else:
                    print("%s (CWD: %s)" % (path.rawpath(), path.base))
        return False
    return True


class file_use_record:
    FUSE_ABS_REF = 1 << 0
    FUSE_STAT = 1 << 1
    FUSE_READ_DATA = 1 << 2
    FUSE_WRITE_DATA = 1 << 3
    FUSE_CREATE = 1 << 4
    FUSE_REMOVE = 1 << 5
    FUSE_OPEN = 1 << 6

    def __init__(self):
        self.fuse = 0

    def has_abs_ref(self):
        return self.fuse & self.FUSE_ABS_REF

    def has_stat(self):
        return self.fuse & self.FUSE_STAT

    def has_read_data(self):
        return self.fuse & self.FUSE_READ_DATA

    def has_write_data(self):
        return self.fuse & self.FUSE_WRITE_DATA

    def has_create(self):
        return self.fuse & self.FUSE_CREATE

    def has_remove(self):
        return self.fuse & self.FUSE_REMOVE

    def has_open(self):
        return self.fuse & self.FUSE_OPEN

    @classmethod
    def build_from_str(cls, fuse_str):
        # type: (str) -> file_use_record
        name_2_bit = {
            "FUSE_STAT": cls.FUSE_STAT,
            "FUSE_READ_DATA": cls.FUSE_READ_DATA,
            "FUSE_WRITE_DATA": cls.FUSE_WRITE_DATA,
            "FUSE_CREATE": cls.FUSE_CREATE,
            "FUSE_REMOVE": cls.FUSE_REMOVE,
            "FUSE_OPEN": cls.FUSE_OPEN,
            "FUSE_ABS_REF": cls.FUSE_ABS_REF,
        }

        fuse_str.strip()
        fuse_field_strs = map(lambda _s: _s.strip(), fuse_str.strip().split("|"))
        new_fuse_rec = cls()
        for fuse_field_str in fuse_field_strs:
            new_fuse_rec.fuse |= name_2_bit[fuse_field_str]

        return new_fuse_rec

    def __str__(self):
        comp_set = (
            (self.FUSE_STAT, "FUSE_STAT"),
            (self.FUSE_READ_DATA, "FUSE_READ_DATA"),
            (self.FUSE_WRITE_DATA, "FUSE_WRITE_DATA"),
            (self.FUSE_CREATE, "FUSE_CREATE"),
            (self.FUSE_REMOVE, "FUSE_REMOVE"),
            (self.FUSE_OPEN, "FUSE_OPEN"),
            (self.FUSE_ABS_REF, "FUSE_ABS_REF"),
        )
        field = []
        for fuse_bit, fuse_str in comp_set:
            if fuse_bit & self.fuse:
                field.append(fuse_str)
        return " | ".join(field)


def check_file_usage(analyzer, tree_root, print_info=False):
    # type: (scall_trace_analyzer, str, bool) -> Dict[str, file_use_record]
    from ..syscalls.sys_read import sys_read
    from ..syscalls.sys_pread import sys_pread
    from ..syscalls.sys_write import sys_write
    from ..syscalls.sys_pwrite import sys_pwrite
    from ..syscalls.sys_lseek import sys_lseek
    from ..syscalls.sys_fstat import sys_fstat
    from ..syscalls.sys_fcntl import sys_fcntl
    from ..syscalls.sys_ftruncate import sys_ftruncate
    from ..syscalls.sys_lstat import sys_lstat
    from ..syscalls.sys_fstatat import sys_fstatat
    from ..syscalls.sys_faccessat import sys_faccessat
    from ..syscalls.sys_linkat import sys_linkat
    from ..syscalls.sys_unlinkat import sys_unlinkat
    from ..syscalls.sys_mkdirat import sys_mkdirat
    from ..syscalls.sys_renameat2 import sys_renameat2

    file_usage_info = defaultdict(file_use_record)

    def record_file_stat(_f):
        file_usage_info[
            _f.abspath()].fuse |= file_use_record.FUSE_STAT | (file_use_record.FUSE_ABS_REF if _f.isabs() else 0)

    def record_file_read_data(_f):
        file_usage_info[
            _f.abspath()].fuse |= file_use_record.FUSE_READ_DATA | (file_use_record.FUSE_ABS_REF if _f.isabs() else 0)

    def record_file_write_data(_f):
        file_usage_info[
            _f.abspath()].fuse |= file_use_record.FUSE_WRITE_DATA | (file_use_record.FUSE_ABS_REF if _f.isabs() else 0)

    def record_file_create(_f):
        file_usage_info[
            _f.abspath()].fuse |= file_use_record.FUSE_CREATE | (file_use_record.FUSE_ABS_REF if _f.isabs() else 0)

    def record_file_remove(_f):
        file_usage_info[
            _f.abspath()].fuse |= file_use_record.FUSE_REMOVE | (file_use_record.FUSE_ABS_REF if _f.isabs() else 0)

    def record_file_open(_f):
        file_usage_info[
            _f.abspath()].fuse |= file_use_record.FUSE_OPEN | (file_use_record.FUSE_ABS_REF if _f.isabs() else 0)

    def record_nothing(_f):
        pass

    for scall in analyzer.syscalls:
        if not scall.is_success():
            continue
        # pathname reference analysis
        if isinstance(scall, sys_faccessat) or isinstance(scall, sys_fstatat) or isinstance(scall, sys_lstat):
            record_file_stat(scall.get_arg_paths()[0])
        elif isinstance(scall, sys_mkdirat):
            record_file_create(scall.get_arg_paths()[0])
        elif isinstance(scall, sys_linkat):
            link_info = scall.get_arg_paths()
            record_file_stat(link_info[0])
            record_file_create(link_info[1])
        elif isinstance(scall, sys_renameat2):
            rename_info = scall.get_arg_paths()
            record_file_remove(rename_info[0])
            record_file_create(rename_info[1])
        elif isinstance(scall, sys_unlinkat):
            record_file_remove(scall.get_arg_paths()[0])

        # fd def-use analysis
        if isinstance(scall, s.mixin_syscall_def_fd):
            if isinstance(scall, sys_fcntl) and not scall.is_dupfd():
                continue

            fd_path = scall.def_fd_get_path()
            record_file_open(fd_path)
            if scall.def_fd_get_flags() & os.O_CREAT:
                record_file_create(fd_path)

            for fd_use in scall.use_list:
                if not fd_use.is_success():
                    continue
                fd_use_type = type(fd_use)
                {
                    sys_write: record_file_write_data,
                    sys_pwrite: record_file_write_data,
                    sys_ftruncate: record_file_write_data,
                    sys_read: record_file_read_data,
                    sys_pread: record_file_read_data,
                    sys_fstat: record_file_stat,
                    sys_fcntl: record_nothing,
                    sys_lseek: record_nothing,
                }.get(fd_use_type, record_file_open)(fd_path)

    def convert_rel_path(_p):
        # type: (str) -> str
        if _p.startswith(tree_root):
            return os.path.relpath(_p, tree_root)
        else:
            return _p

    file_usage_info_relpath = dict()
    for k, v in file_usage_info.items():
        file_usage_info_relpath[convert_rel_path(k)] = v

    if print_info:
        for k, v in file_usage_info_relpath.items():
            print("\"%s\" - %s" % (k, v))
    return file_usage_info_relpath


@click.command()
@click.argument("input_file", type=click.File())
@click.option('--echo', is_flag=True, help='echo the decoded scall trace.')
# @click.option("-c", '--cwd', "cwd_path", type=click.Path(exists=True),
#               help='the CWD used for evaluate out-of-tree file access.')
def main(input_file, echo):
    cwd_path = os.path.abspath(os.path.dirname(input_file.name))

    trace_analyzer = scall_trace_analyzer(cwd_path)
    strace_str = input_file.read()

    trace_analyzer.parse_strace_str(strace_str)
    if echo:
        for t in trace_analyzer.syscalls:
            print(str(t))

    has_warning = False

    has_warning |= check_abs_path_reference(trace_analyzer, print_info=True)
    print()
    has_warning |= check_out_of_tree_reference(trace_analyzer, cwd_path, print_info=True)
    print()
    file_use_stat = check_file_usage(trace_analyzer, cwd_path, print_info=True)
    print()


if __name__ == '__main__':
    main()
