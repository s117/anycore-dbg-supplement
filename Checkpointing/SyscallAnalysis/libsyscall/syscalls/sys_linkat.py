from . import syscall as s


# int linkat(int olddirfd, const char *oldpath,
#            int newdirfd, const char *newpath, int flags);
@s.mixedomatic
class sys_linkat(s.syscall, s.mixin_syscall_has_path_args, s.mixin_syscall_use_fd):
    def __init__(self, name, args, ret, syscall_id, at_cwd, seq_no):
        super().__init__(name, args, ret, syscall_id, at_cwd, seq_no)
        self.olddirfd = args[0].avalue
        self.oldpath = args[1].amemval
        self.newdirfd = args[2].avalue
        self.newpath = args[3].amemval
        self.flags = args[4].avalue

    def is_success(self):
        return self.ret == 0

    def get_arg_paths(self):
        return [
            s.path(self.def_list[0].def_fd_get_path().abspath(), self.oldpath),
            s.path(self.def_list[1].def_fd_get_path().abspath(), self.newpath)
        ]

    def use_fd_get_fds(self):
        return [
            self.olddirfd,
            self.newdirfd
        ]
