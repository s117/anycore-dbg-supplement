from typing import Dict, Any, Optional, Callable, Tuple, Union
import pathlib

from ..syscalls import syscall
from ..syscalls.sys_openat import sys_openat
from ..syscalls.sys_fcntl import sys_fcntl
from ..syscalls.sys_close import sys_close
from ..syscalls.sys_chdir import sys_chdir


class FileDescriptorTracker:
    def __init__(self, initial_cwd):
        # type: (str) -> None
        self.active_fds = dict()  # type: Dict[int, Tuple[str, int, Optional[Union[syscall.syscall, syscall.mixin_syscall_def_fd]]]]

        self.triggers = {
            "sys_openat": self.on_sys_openat,
            "sys_fcntl": self.on_sys_fcntl,
            "sys_close": self.on_sys_close,
            "sys_chdir": self.on_sys_chdir,
        }  # type: Dict[str, Callable[[Any], None]]

        assert pathlib.PurePosixPath(initial_cwd).is_absolute()
        self.on_sys_chdir(
            sys_chdir(
                name="sys_chdir",
                args=[syscall.arg_ptr("path", "path_in_t", 0, initial_cwd)],
                ret=0,
                syscall_id=49,
                at_cwd=initial_cwd,
                seq_no=-1
            )
        )

    def getcwd(self):
        # type: () -> str
        return self.active_fds[syscall.AT_FDCWD][0]

    def lookup_def(self, fd):
        # type: (int) -> Optional[Union[syscall.syscall, syscall.mixin_syscall_def_fd]]
        if fd in self.active_fds:
            return self.active_fds[fd][2]
        return None

    def lookup_path(self, fd):
        # type: (int) -> Optional[str]
        if fd in self.active_fds:
            return self.active_fds[fd][0]
        return None

    def lookup_flags(self, fd):
        # type: (int) -> Optional[int]
        if fd in self.active_fds:
            return self.active_fds[fd][1]
        return None

    def on_sys_openat(self, s):
        # type: (sys_openat) -> None
        assert isinstance(s, sys_openat)
        if not s.is_success():
            return
        new_fd = s.new_fd()
        assert new_fd not in self.active_fds
        assert s.dirfd in self.active_fds

        self.active_fds[new_fd] = (
            s.def_fd_get_path().abspath(),
            s.def_fd_get_flags(),
            s
        )

    def on_sys_fcntl(self, s):
        # type: (sys_fcntl) -> None
        if s.is_dupfd() and s.is_dupfd_success():
            assert s.dupfd_oldfd() in self.active_fds

            self.active_fds[s.dupfd_newfd()] = (
                s.def_fd_get_path().abspath(),
                s.def_fd_get_flags(),
                s
            )

    def on_sys_close(self, s):
        # type: (sys_close) -> None
        # close fd
        if s.is_success():
            closing_fd = s.closing_fd()
            assert closing_fd != syscall.AT_FDCWD
            assert closing_fd in self.active_fds
            self.active_fds.pop(closing_fd)

    def on_sys_chdir(self, s):
        # type: (sys_chdir) -> None
        # update cwd as needed
        if s.is_success():
            self.active_fds[syscall.AT_FDCWD] = (
                s.def_fd_get_path().abspath(),
                s.def_fd_get_flags(),
                s
            )

    def on_syscall(self, s, start, end):
        # type: (syscall.syscall, int, int) -> None
        syscall_name = s.name
        if syscall_name in self.triggers:
            self.triggers[syscall_name](s)

    def generate_report(self):
        # type: () -> str
        ret = ["fd - path"]
        for k, v in self.active_fds.items():
            ret.append("%d - %s" % (k, v))
        return "\n".join(ret)
