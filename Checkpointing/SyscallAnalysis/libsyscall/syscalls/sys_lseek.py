from . import syscall as s


# off_t lseek(int fd, off_t offset, int whence);
@s.mixedomatic
class sys_lseek(s.syscall, s.mixin_syscall_use_fd):
    def __init__(self, name, args, ret, syscall_id, at_cwd, seq_no):
        super().__init__(name, args, ret, syscall_id, at_cwd, seq_no)
        self.fd = args[0].avalue
        self.offset = args[1].avalue
        self.whence = args[2].avalue

    def is_success(self):  # type: () -> bool
        return self.ret != -1

    def use_fd_get_fds(self):
        return [self.fd]
