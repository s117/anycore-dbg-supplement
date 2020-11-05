from . import syscall as s


# ssize_t pread(int fd, void *buf, size_t count, off_t offset);
@s.mixedomatic
class sys_pread(s.syscall, s.mixin_syscall_use_fd):
    def __init__(self, name, args, ret, syscall_id, at_cwd, seq_no):
        super().__init__(name, args, ret, syscall_id, at_cwd, seq_no)
        self.fd = args[0].avalue
        self.count = args[2].avalue
        self.offset = args[3].avalue

    def is_success(self):  # type: () -> bool
        return self.ret != -1

    def use_fd_get_fds(self):
        return [self.fd]
