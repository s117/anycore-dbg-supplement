#!/usr/bin/env python3

import os
import fcntl
from typing import List, Any

import click
import typing
from pyparsing import *
from libsyscall.analyzer.strace_parser import strace_parser


class scall_consumer:
    def on_syscall(self, s, start, end):
        # type: (ParseResults, int, int) -> None
        raise NotImplementedError

    def get_consumer_name(self):
        # type: () -> Optional[str]
        raise NotImplementedError

    def generate_report(self):
        # type: () -> str
        raise NotImplementedError


class fd_tracker(scall_consumer):
    RISCV_AT_FDCWD = -100

    def __init__(self, cwd):
        self.fds = dict()  # type: typing.Dict[int, List[Any]]

        self.triggers = {
            "sys_openat": self.on_sys_openat,
            "sys_fcntl": self.on_sys_fcntl,
            "sys_close": self.on_sys_close,
            "sys_chdir": self.on_sys_chdir,
        }  # type: typing.Dict[str, typing.Callable[[Any], None]]

        assert os.path.isabs(cwd)
        self._set_analysis_cwd(cwd)

    def getcwd(self):
        return self.fds[self.RISCV_AT_FDCWD][0]

    def _set_analysis_cwd(self, p):
        self.fds[self.RISCV_AT_FDCWD] = [p, os.O_CLOEXEC | os.O_DIRECTORY | os.O_NONBLOCK]

    def abspath(self, path, base=None):
        if base is None:
            base = self.getcwd()

        if os.path.isabs(path):
            return path
        else:
            return os.path.abspath(
                os.path.join(base, path)
            )

    def lookup(self, fd):
        if fd in self.fds:
            return tuple(self.fds[fd])
        return None

    def lookup_path(self, fd):
        # type: (int) -> typing.Optional[str]
        if fd in self.fds:
            return self.fds[fd][0]
        return None

    def lookup_flags(self, fd):
        # type: (int) -> typing.Optional[int]
        if fd in self.fds:
            return self.fds[fd][1]
        return None

    def on_sys_openat(self, s):
        if s.ret_code <= 0:
            return
        scall_args = s.syscall_args
        newfd = s.ret_code
        dirfd = scall_args[0].arg_val
        pathname = scall_args[1].arg_memval
        flags = scall_args[2].arg_val

        assert newfd not in self.fds
        assert dirfd in self.fds

        new_fd_record = [
            self.abspath(pathname, self.lookup_path(dirfd)),
            flags
        ]

        self.fds[newfd] = new_fd_record

    def on_sys_fcntl(self, s):
        scall_args = s.syscall_args
        fcntl_fd = scall_args[0].arg_val
        fcntl_cmd = scall_args[1].arg_val
        fcntl_arg = scall_args[2].arg_val
        fcntl_ret = s.ret_code
        if fcntl_cmd in {fcntl.F_DUPFD, fcntl.F_DUPFD_CLOEXEC}:
            if fcntl_ret > 0:
                # duplicated file shares the same flags with the original
                assert fcntl_ret not in self.fds
                assert fcntl_fd in self.fds
                self.fds[fcntl_ret] = self.fds[fcntl_fd]
        elif fcntl_cmd == fcntl.F_SETFL:
            if fcntl_ret == 0:
                assert fcntl_fd in self.fds
                # only those flags can be set by SETFL on linux
                setting_mask = fcntl_arg & (os.O_APPEND | os.O_ASYNC | os.O_DIRECT | os.O_NOATIME | os.O_NONBLOCK)
                old_flags = self.lookup_flags(fcntl_fd)

                new_flags = (old_flags & ~(os.O_APPEND | os.O_ASYNC | os.O_DIRECT | os.O_NOATIME | os.O_NONBLOCK))
                new_flags |= setting_mask

    def on_sys_close(self, s):
        # close fd
        if s.ret_code != 0:
            return
        scall_args = s.syscall_args

        closed_fd = scall_args[0].arg_val
        assert closed_fd != self.RISCV_AT_FDCWD
        assert closed_fd in self.fds
        self.fds.pop(closed_fd)

    def on_sys_chdir(self, s):
        # update cwd as needed
        if s.ret_code != 0:
            return
        scall_args = s.syscall_args
        newpath = scall_args[0].arg_memval

        newcwd = self.abspath(newpath)
        self._set_analysis_cwd(newcwd)

    def on_syscall(self, s, start, end):
        # type: (ParseResults, int, int) -> None
        syscall_name = s.syscall_name
        if syscall_name in self.triggers:
            self.triggers[syscall_name](s)

    def get_consumer_name(self):
        return None

    def generate_report(self):
        # type: () -> str
        ret = ["fd - path"]
        for k, v in self.fds.items():
            ret.append("%d - %s" % (k, v))
        return "\n".join(ret)


path_whitelist = {
    "/etc/localtime"
}


class verify_abs_path_reference(scall_consumer):
    path_type = {"path_in_t", "path_out_t"}

    def __init__(self, fd_res):
        # type: (fd_tracker) -> None
        self.syscalls_with_abspath_ref = list()
        self.fd_res = fd_res

    def get_consumer_name(self):
        return "Absolute path reference checker"

    def is_abspath(self, pname):
        # type: (str) -> bool
        if pname in path_whitelist:
            return False
        return os.path.isabs(pname)

    def on_syscall(self, s, start, end):
        for arg in s.syscall_args:
            if arg.arg_type in self.path_type:
                if self.is_abspath(arg.arg_memval):
                    self.syscalls_with_abspath_ref.append(s)
                    break

    def generate_report(self):
        if self.syscalls_with_abspath_ref:
            ret = []
            # ret = ["Warning: the following syscall contains absolute path reference:"]
            for idx, s in enumerate(self.syscalls_with_abspath_ref, start=1):
                ret.append("--- %s ---" % idx)
                ret.append(strace_parser.stringify(s))
        else:
            ret = ["Pass"]

        return "\n".join(ret)


class verify_out_of_tree_access(scall_consumer):
    def __init__(self, base, fd_res):
        # type: (str, fd_tracker) -> None
        assert os.path.isabs(base)
        self.base_path = base

        self.fd_res = fd_res
        self.analyzers = {
            "sys_lstat": self.handle_pname,
            "sys_chdir": self.handle_pname,
            "sys_openat": self.handle_dirfd_pname,
            "sys_fstatat": self.handle_dirfd_pname,
            "sys_faccessat": self.handle_dirfd_pname,
            "sys_mkdirat": self.handle_dirfd_pname,
            "sys_unlinkat": self.handle_dirfd_pname,
            "sys_linkat": self.handle_oldnew_dirfd_pname,
            "sys_renameat2": self.handle_oldnew_dirfd_pname,
        }  # type: typing.Dict[str, typing.Callable[[Any], None]]
        self.syscall_with_out_tree_ref = list()

    def get_consumer_name(self):
        return "Out-of-tree path access checker"

    def is_out_of_tree_access(self, pname):
        # type: (str) -> bool
        if pname in path_whitelist:
            return False
        return not pname.startswith(self.base_path)

    def handle_pname(self, s):
        sargs = s.syscall_args
        pname = sargs[0].arg_memval
        abspath = self.fd_res.abspath(pname)
        if self.is_out_of_tree_access(abspath):
            self.syscall_with_out_tree_ref.append(s)

    def handle_dirfd_pname(self, s):
        sargs = s.syscall_args
        dirfd = sargs[0].arg_val
        pname = sargs[1].arg_memval
        dirfd_pname = self.fd_res.lookup_path(dirfd)
        abspath = self.fd_res.abspath(pname, dirfd_pname)
        if self.is_out_of_tree_access(abspath):
            self.syscall_with_out_tree_ref.append(s)

    def handle_oldnew_dirfd_pname(self, s):
        sargs = s.syscall_args
        odirfd = sargs[0].arg_val
        poname = sargs[1].arg_memval
        ndirfd = sargs[2].arg_val
        pnname = sargs[3].arg_memval
        odirfd_pname = self.fd_res.lookup_path(odirfd)
        ndirfd_pname = self.fd_res.lookup_path(ndirfd)
        oabspath = self.fd_res.abspath(poname, odirfd_pname)
        nabspath = self.fd_res.abspath(pnname, ndirfd_pname)
        if self.is_out_of_tree_access(oabspath) or self.is_out_of_tree_access(nabspath):
            self.syscall_with_out_tree_ref.append(s)

    def on_syscall(self, s, start, end):
        syscall_name = s.syscall_name
        if syscall_name in self.analyzers:
            self.analyzers[syscall_name](s)

    def generate_report(self):
        if self.syscall_with_out_tree_ref:
            ret = []
            # ret = ["Warning: the following syscall contains out of tree reference:"]
            for idx, s in enumerate(self.syscall_with_out_tree_ref, start=1):
                ret.append("--- %s ---" % idx)
                ret.append(strace_parser.stringify(s))
        else:
            ret = ["Pass"]

        return "\n".join(ret)


class file_mod_detect(scall_consumer):
    def __init__(self, fd_res):
        # type: (fd_tracker) -> None
        self.fd_res = fd_res
        self.analyzers = {
            "sys_openat": self.on_sys_open,
            "sys_unlinkat": self.on_sys_unlink,
            "sys_renameat2": self.on_sys_renameat2,
        }  # type: typing.Dict[str, typing.Callable[[Any], None]]
        self.modified_file_list = list()

    def get_consumer_name(self):
        return "FS modification checker"

    OPENAT_FLAGS_COMP_SET = (
        (os.O_RDONLY, "O_RDONLY"),
        (os.O_WRONLY, "O_WRONLY"),
        (os.O_RDWR, "O_RDWR"),
        (os.O_APPEND, "O_APPEND"),
        (os.O_ASYNC, "O_ASYNC"),
        (os.O_CLOEXEC, "O_CLOEXEC"),
        (os.O_CREAT, "O_CREAT"),
        (os.O_DIRECT, "O_DIRECT"),
        (os.O_DIRECTORY, "O_DIRECTORY"),
        (os.O_DSYNC, "O_DSYNC"),
        (os.O_EXCL, "O_EXCL"),
        (os.O_LARGEFILE, "O_LARGEFILE"),
        (os.O_NOATIME, "O_NOATIME"),
        (os.O_NOCTTY, "O_NOCTTY"),
        (os.O_NOFOLLOW, "O_NOFOLLOW"),
        (os.O_NONBLOCK, "O_NONBLOCK"),
        (os.O_NDELAY, "O_NDELAY"),
        (os.O_PATH, "O_PATH"),
        (os.O_SYNC, "O_SYNC"),
        (os.O_TMPFILE, "O_TMPFILE"),
        (os.O_TRUNC, "O_TRUNC"),
    )

    def open_flags_decode(self, flags):
        fset = []
        for m, s in self.OPENAT_FLAGS_COMP_SET:
            if m & flags:
                fset.append(s)

        return " | ".join(fset)

    def on_sys_open(self, s):
        sargs = s.syscall_args
        ret_code = s.ret_code
        dirfd = sargs[0].arg_val
        pname = sargs[1].arg_memval
        flags = sargs[2].arg_val
        dirfd_pname = self.fd_res.lookup_path(dirfd)
        abspath = self.fd_res.abspath(pname, dirfd_pname)

        if ret_code >= 0:
            if (flags & os.O_WRONLY) or (flags & os.O_RDWR):
                self.modified_file_list.append((s, "[%s] %s" % (self.open_flags_decode(flags), abspath)))

    def on_sys_unlink(self, s):
        sargs = s.syscall_args
        ret_code = s.ret_code
        dirfd = sargs[0].arg_val
        pname = sargs[1].arg_memval
        dirfd_pname = self.fd_res.lookup_path(dirfd)
        abspath = self.fd_res.abspath(pname, dirfd_pname)
        if ret_code == 0:
            self.modified_file_list.append((s, abspath))

    def on_sys_renameat2(self, s):
        sargs = s.syscall_args
        ret_code = s.ret_code
        odirfd = sargs[0].arg_val
        poname = sargs[1].arg_memval
        ndirfd = sargs[2].arg_val
        pnname = sargs[3].arg_memval
        odirfd_pname = self.fd_res.lookup_path(odirfd)
        ndirfd_pname = self.fd_res.lookup_path(ndirfd)
        oabspath = self.fd_res.abspath(poname, odirfd_pname)
        nabspath = self.fd_res.abspath(pnname, ndirfd_pname)
        if ret_code == 0:
            self.modified_file_list.append((s, "%s -> %s" % (oabspath, nabspath)))

    def on_syscall(self, s, start, end):
        syscall_name = s.syscall_name
        if syscall_name in self.analyzers:
            self.analyzers[syscall_name](s)

    def generate_report(self):
        if self.modified_file_list:
            ret = []
            # ret = ["Warning: the following syscall contains out of tree reference:"]
            for idx, s in enumerate(self.modified_file_list, start=1):
                syscall, str_desc = s
                ret.append("--- %s ---" % idx)
                ret.append("@%s" % str_desc)
                ret.append(strace_parser.stringify(syscall))
        else:
            ret = ["Pass"]

        return "\n".join(ret)


class echo_out(scall_consumer):
    def __init__(self):
        pass

    def get_consumer_name(self):
        return None

    def on_syscall(self, s, start, end):
        print(strace_parser.stringify(s))

    def generate_report(self):
        pass


def append_to_file(filename, content):
    with open(filename, mode="a") as of:
        of.write(content)
        of.write("\n")


@click.command()
@click.argument("input_file", type=click.File())
@click.option('--echo', is_flag=True, help='echo the decoded scall trace.')
# @click.option("-c", '--cwd', "cwd_path", type=click.Path(exists=True),
#               help='the CWD used for evaluate out-of-tree file access.')
def main(input_file, echo):
    cwd_path = os.path.abspath(os.path.dirname(input_file.name))

    fd_res = fd_tracker(cwd=cwd_path)

    applied_analysis = [
        verify_abs_path_reference(fd_res),
        verify_out_of_tree_access(cwd_path, fd_res),
        file_mod_detect(fd_res)
    ]  # type: List[scall_consumer]

    analysis_stat_file = [
        "abs_path_check.txt",
        "out_tree_check.txt",
        "file_mod_check.txt",
    ]

    if echo:
        applied_analysis.append(echo_out())

    strace_str = input_file.read()
    for i, start, end in strace_parser.parse(strace_str):
        if i:
            fd_res.on_syscall(i, start, end)
            for a in applied_analysis:
                a.on_syscall(i, start, end)

    bmark_name = os.path.basename(cwd_path)
    print(("<%s>" % bmark_name))
    print("")

    passed = True
    for a, dumpfile in zip(applied_analysis, analysis_stat_file):
        analysis_name = a.get_consumer_name()
        if analysis_name:
            print(("**** Report from [%s] " % analysis_name).ljust(80, "*"))
            rpt = a.generate_report()
            print(rpt)
            print("*" * 80)
            print("")
            if rpt != "Pass":
                passed = False
            else:
                append_to_file(dumpfile, bmark_name)

    print("\n\n\n")

    if passed:
        append_to_file("all_passed.txt", bmark_name)


if __name__ == '__main__':
    main()
