from . import syscall as s


# int getdents64(unsigned int fd, struct linux_dirent64 *dirp, unsigned int count);
@s.mixedomatic
class sys_getdents64(s.syscall, s.mixin_syscall_use_fd):
    def __init__(self, name, args, ret, syscall_id, at_cwd, seq_no):
        super().__init__(name, args, ret, syscall_id, at_cwd, seq_no)
        self.fd = args[0].avalue

    def is_success(self):
        return self.ret != -1

    def use_fd_get_fds(self):
        return [self.fd]
