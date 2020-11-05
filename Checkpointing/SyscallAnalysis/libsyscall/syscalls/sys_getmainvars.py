from . import syscall as s


# int getmainvars(char *buf, unsigned int limit);
@s.mixedomatic
class sys_getmainvars(s.syscall):
    def __init__(self, name, args, ret, syscall_id, at_cwd, seq_no):
        super().__init__(name, args, ret, syscall_id, at_cwd, seq_no)

    def is_success(self):  # type: () -> bool
        return True
