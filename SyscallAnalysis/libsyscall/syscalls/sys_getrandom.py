from . import syscall as s


# ssize_t getrandom(void *buf, size_t buflen, unsigned int flags);
@s.mixedomatic
class sys_getrandom(s.syscall):
    def __init__(self, name, args, ret, syscall_id, at_cwd, seq_no):
        super().__init__(name, args, ret, syscall_id, at_cwd, seq_no)
        self.flags = args[2].avalue

    def is_success(self):  # type: () -> bool
        return self.ret != -1
