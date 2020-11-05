from . import syscall as s


# int fstatat(int dirfd, const char *pathname, struct stat *statbuf, int flags);
@s.mixedomatic
class sys_fstatat(s.syscall, s.mixin_syscall_has_path_args, s.mixin_syscall_use_fd):
    def __init__(self, name, args, ret, syscall_id, at_cwd, seq_no):
        super().__init__(name, args, ret, syscall_id, at_cwd, seq_no)
        self.dirfd = args[0].avalue
        self.pathname = args[1].amemval
        self.flags = args[2].avalue

    def is_success(self):
        return self.ret == 0

    def get_arg_paths(self):
        return [s.path(self.def_list[0].def_fd_get_path().abspath(), self.pathname)]

    def use_fd_get_fds(self):
        return [self.dirfd]
