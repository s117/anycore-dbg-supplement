from . import syscall as s


# int close(int fd);
@s.mixedomatic
class sys_close(s.syscall, s.mixin_syscall_use_fd):
    def __init__(self, name, args, ret, syscall_id, at_cwd, seq_no):
        super().__init__(name, args, ret, syscall_id, at_cwd, seq_no)
        self.target_fd = args[0].avalue

    def is_success(self):
        return self.ret == 0

    def closing_fd(self):
        return self.target_fd

    def use_fd_get_fds(self):
        return [self.closing_fd()]
