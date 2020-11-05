from . import syscall as s


# char *getcwd(char *buf, size_t size);
@s.mixedomatic
class sys_getcwd(s.syscall):
    def __init__(self, name, args, ret, syscall_id, at_cwd, seq_no):
        super().__init__(name, args, ret, syscall_id, at_cwd, seq_no)

    def is_success(self):
        return self.ret != 0
