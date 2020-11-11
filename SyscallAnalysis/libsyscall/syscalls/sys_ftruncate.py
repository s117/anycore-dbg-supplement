from . import syscall as s


# int ftruncate(int fd, off_t length);
@s.mixedomatic
class sys_ftruncate(s.syscall, s.mixin_syscall_use_fd):
    def __init__(self, name, args, ret, syscall_id, at_cwd, seq_no):
        super().__init__(name, args, ret, syscall_id, at_cwd, seq_no)
        self.fd = args[0].avalue
        self.length = args[1].avalue

    def is_success(self):
        return self.ret == 0

    def use_fd_get_fds(self):
        return [self.fd]
