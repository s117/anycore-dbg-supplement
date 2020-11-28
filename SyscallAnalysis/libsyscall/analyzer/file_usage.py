#!/usr/bin/env python3
import os
import pathlib
from collections import defaultdict
from typing import Dict, List

import click
from ..syscalls import syscall as s
from .syscall_trace_constructor import SyscallTraceConstructor


class FileUsageInfo:
    FUSE_ABS_REF = 1 << 0
    FUSE_STAT = 1 << 1
    FUSE_READ_DATA = 1 << 2
    FUSE_WRITE_DATA = 1 << 3
    FUSE_CREATE = 1 << 4
    FUSE_REMOVE = 1 << 5
    FUSE_OPEN_RD = 1 << 6
    FUSE_OPEN_WR = 1 << 7
    FUSE_OPEN_RW = 1 << 8

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

    def has_open_rd(self):
        return self.fuse & self.FUSE_OPEN_RD

    def has_open_wr(self):
        return self.fuse & self.FUSE_OPEN_WR

    def has_open_rw(self):
        return self.fuse & self.FUSE_OPEN_RW

    @classmethod
    def build_from_str(cls, fuse_str):
        # type: (str) -> FileUsageInfo
        name_2_bit = {
            "FUSE_STAT": cls.FUSE_STAT,
            "FUSE_READ_DATA": cls.FUSE_READ_DATA,
            "FUSE_WRITE_DATA": cls.FUSE_WRITE_DATA,
            "FUSE_CREATE": cls.FUSE_CREATE,
            "FUSE_REMOVE": cls.FUSE_REMOVE,
            "FUSE_OPEN_RD": cls.FUSE_OPEN_RD,
            "FUSE_OPEN_WR": cls.FUSE_OPEN_WR,
            "FUSE_OPEN_RW": cls.FUSE_OPEN_RW,
            "FUSE_ABS_REF": cls.FUSE_ABS_REF,
        }

        fuse_str.strip()
        fuse_field_strs = map(lambda _s: _s.strip(), fuse_str.strip().split("|"))
        new_fuse_rec = cls()
        try:
            for fuse_field_str in fuse_field_strs:
                new_fuse_rec.fuse |= name_2_bit[fuse_field_str]
        except Exception:
            raise ValueError("%s is not a valid file usage description" % fuse_str)

        return new_fuse_rec

    def __str__(self):
        comp_set = (
            (self.FUSE_STAT, "FUSE_STAT"),
            (self.FUSE_READ_DATA, "FUSE_READ_DATA"),
            (self.FUSE_WRITE_DATA, "FUSE_WRITE_DATA"),
            (self.FUSE_CREATE, "FUSE_CREATE"),
            (self.FUSE_REMOVE, "FUSE_REMOVE"),
            (self.FUSE_OPEN_RD, "FUSE_OPEN_RD"),
            (self.FUSE_OPEN_WR, "FUSE_OPEN_WR"),
            (self.FUSE_OPEN_RW, "FUSE_OPEN_RW"),
            (self.FUSE_ABS_REF, "FUSE_ABS_REF"),
        )
        field = []
        for fuse_bit, fuse_str in comp_set:
            if fuse_bit & self.fuse:
                field.append(fuse_str)
        return " | ".join(field)


def stat_file_usage(syscalls, print_info=False):
    # type: (List[s.syscall], bool) -> Dict[str, FileUsageInfo]
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

    file_usage_info = defaultdict(FileUsageInfo)

    def _abs_bit(_f):
        return FileUsageInfo.FUSE_ABS_REF if _f.isabs() else 0

    def record_file_stat(_f):
        file_usage_info[_f.abspath()].fuse |= FileUsageInfo.FUSE_STAT | _abs_bit(_f)

    def record_file_read_data(_f):
        file_usage_info[_f.abspath()].fuse |= FileUsageInfo.FUSE_READ_DATA | _abs_bit(_f)

    def record_file_write_data(_f):
        file_usage_info[_f.abspath()].fuse |= FileUsageInfo.FUSE_WRITE_DATA | _abs_bit(_f)

    def record_file_create(_f):
        file_usage_info[_f.abspath()].fuse |= FileUsageInfo.FUSE_CREATE | _abs_bit(_f)

    def record_file_remove(_f):
        file_usage_info[_f.abspath()].fuse |= FileUsageInfo.FUSE_REMOVE | _abs_bit(_f)

    def record_file_open(_f, acc_mode):
        if acc_mode == os.O_RDONLY:
            file_usage_info[_f.abspath()].fuse |= FileUsageInfo.FUSE_OPEN_RD | _abs_bit(_f)
        elif acc_mode == os.O_WRONLY:
            file_usage_info[_f.abspath()].fuse |= FileUsageInfo.FUSE_OPEN_WR | _abs_bit(_f)
        elif acc_mode == os.O_RDWR:
            file_usage_info[_f.abspath()].fuse |= FileUsageInfo.FUSE_OPEN_RW | _abs_bit(_f)
        else:
            assert False

    def record_nothing(_f):
        pass

    for scall in syscalls:
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
            record_file_open(
                fd_path,
                s.mixin_syscall_def_fd.O_ACCMODE & scall.def_fd_get_flags()
            )
            if scall.def_fd_get_flags() & os.O_CREAT:
                record_file_create(fd_path)

            for fd_use in scall.use_list:
                if fd_use.is_success():
                    {
                        sys_write: record_file_write_data,
                        sys_pwrite: record_file_write_data,
                        sys_ftruncate: record_file_write_data,
                        sys_read: record_file_read_data,
                        sys_pread: record_file_read_data,
                        sys_fstat: record_file_stat,
                        sys_fcntl: record_nothing,
                        sys_lseek: record_nothing,
                    }.get(type(fd_use), record_nothing)(fd_path)

    if print_info:
        for k, v in file_usage_info.items():
            print("\"%s\" - %s" % (k, v))

    return file_usage_info
