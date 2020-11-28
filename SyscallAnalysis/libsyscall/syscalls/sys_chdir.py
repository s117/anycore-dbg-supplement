import os

from . import syscall as s


# int chdir(const char *path);
@s.mixedomatic
class sys_chdir(s.syscall, s.mixin_syscall_has_path_args, s.mixin_syscall_def_fd):
    # because AT_FDCWD is logically defined by chdir, sys_chdir has mixin_syscall_def_fd
    default_flag = os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY | os.O_NONBLOCK

    def __init__(self, name, args, ret, syscall_id, at_cwd, seq_no):
        super().__init__(name, args, ret, syscall_id, at_cwd, seq_no)
        self.path = args[0].amemval

    def is_success(self):
        return self.ret == 0

    def get_arg_paths(self):
        # base = self.
        return [s.path(self.at_cwd, self.path)]

    def def_fd_get_path(self):
        # type: () -> s.path
        return s.path(self.at_cwd, self.path)

    def def_fd_get_flags(self):
        return self.default_flag
