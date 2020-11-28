import os

from . import syscall as s


# int openat(int dirfd, const char *pathname, int flags, mode_t mode);
@s.mixedomatic
class sys_openat(s.syscall, s.mixin_syscall_has_path_args, s.mixin_syscall_def_fd, s.mixin_syscall_use_fd):
    def __init__(self, name, args, ret, syscall_id, at_cwd, seq_no):
        super().__init__(name, args, ret, syscall_id, at_cwd, seq_no)

        assert syscall_id == 56
        assert len(args) == 4
        arg_pathname = args[1]
        assert isinstance(arg_pathname, s.arg_ptr)
        self.dirfd = args[0].avalue
        self.pathname = arg_pathname.amemval
        self.flags = args[2].avalue
        self.mode = args[3].avalue

    def is_success(self):
        return self.ret >= 0

    def new_fd(self):
        return self.ret

    def def_fd_get_path(self):
        # type: () -> s.path
        return s.path(self.def_list[0].def_fd_get_path().abspath(), self.pathname)

    def get_arg_paths(self):
        return [self.def_fd_get_path()]

    def use_fd_get_fds(self):
        return [self.dirfd]

    def def_fd_get_flags(self):
        return self.flags
