import fcntl
import os

from . import syscall as s


# int fcntl(int fd, int cmd, uint64_t arg);
@s.mixedomatic
class sys_fcntl(s.syscall, s.mixin_syscall_def_fd, s.mixin_syscall_use_fd):
    def __init__(self, name, args, ret, syscall_id, at_cwd, seq_no):
        super().__init__(name, args, ret, syscall_id, at_cwd, seq_no)
        self.target_fd = args[0].avalue
        self.cmd = args[1].avalue
        self.cmd_arg = args[2].avalue

    def is_success(self):
        return self.ret != -1

    def is_dupfd(self):
        return self.cmd in {fcntl.F_DUPFD, fcntl.F_DUPFD_CLOEXEC}

    def is_dupfd_success(self):
        return self.ret >= self.cmd_arg

    def dupfd_oldfd(self):
        return self.target_fd

    def dupfd_newfd(self):
        return self.ret

    def is_setfl(self):
        return self.cmd == fcntl.F_SETFL

    def is_setfl_success(self):
        return self.ret == 0

    def setfl_newflags_ormask(self):
        # only those flags can be set by SETFL on linux
        return self.cmd_arg & (os.O_APPEND | os.O_ASYNC | os.O_DIRECT | os.O_NOATIME | os.O_NONBLOCK)

    def def_fd_get_path(self):
        # type: () -> s.path
        if not self.is_dupfd():
            raise RuntimeError("def_fd_get_path is not provided for fcntl with dupfd command")
        return self.def_list[0].def_fd_get_path()

    def def_fd_get_flags(self):
        if not self.is_dupfd():
            raise RuntimeError("def_fd_get_flags is not provided for fcntl with dupfd command")
        return self.def_list[0].def_fd_get_flags()

    def use_fd_get_fds(self):
        return [self.target_fd]
