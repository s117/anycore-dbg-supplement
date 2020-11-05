from . import syscall as s


# int lstat(const char *pathname, struct stat *statbuf);
@s.mixedomatic
class sys_lstat(s.syscall, s.mixin_syscall_has_path_args):
    def __init__(self, name, args, ret, syscall_id, at_cwd, seq_no):
        super().__init__(name, args, ret, syscall_id, at_cwd, seq_no)
        self.pathname = args[0].amemval

    def is_success(self):  # type: () -> bool
        return self.ret == 0

    def get_arg_paths(self):
        return [s.path(self.at_cwd, self.pathname)]
