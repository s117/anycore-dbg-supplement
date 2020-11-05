from . import syscall as s


# void exit(int status)
@s.mixedomatic
class sys_exit(s.syscall):
    def __init__(self, name, args, ret, syscall_id, at_cwd, seq_no):
        super().__init__(name, args, ret, syscall_id, at_cwd, seq_no)
        self.status = args[0].avalue

    def is_success(self):  # type: () -> bool
        return True

    def ret_code(self):
        return self.status
