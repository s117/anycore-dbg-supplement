import os
from typing import List, Any, Optional, Union

AT_FDCWD = -100


class path:
    def __init__(self, base, pathname):
        # type: (str, str) -> None
        self.base = base
        self.pathname = pathname

    def isabs(self):
        # type: () -> bool
        return os.path.isabs(self.pathname)

    def rawpath(self):
        return self.pathname

    def abspath(self):
        # type: () -> str
        if self.isabs():
            return self.pathname
        else:
            return os.path.abspath(os.path.join(self.base, self.pathname))

    def contains(self, p):
        # type: (path) -> bool
        assert isinstance(p, path)
        p_abspath = p.abspath()
        this_abspath = self.abspath()

        return p_abspath.startswith(this_abspath)

    def __eq__(self, other):
        return isinstance(other, self.__class__) and self.base == other.base and self.pathname == other.pathname

    def __hash__(self):
        return (hash(self.base) << 1) ^ hash(self.pathname)


class arg_val:
    def __init__(self, aname, atype, avalue):
        # type: (str, str, Any) -> None
        self.amemval = None
        self.aname = aname
        self.atype = atype
        self.avalue = avalue


class arg_ptr(arg_val):
    def __init__(self, aname, atype, avalue, amemval):
        # type: (str, str, Any, Any) -> None
        super().__init__(aname, atype, avalue)
        self.amemval = amemval


class syscall:
    def __init__(self, name, args, ret, syscall_id, at_cwd, seq_no):
        # type: (str, List[Union[arg_val, arg_ptr]], int, int, str, int) -> None
        self.name = name
        self.args = args
        self.ret = ret
        self.syscall_id = syscall_id
        self.seq_no = seq_no
        self.at_cwd = at_cwd

    def __str__(self):
        ret = ["[%d] %s (" % (self.syscall_id, self.name)]
        for arg in self.args:
            arg_line = "  %s %s = " % (arg.atype, arg.aname)
            if isinstance(arg, arg_ptr):
                arg_line += "%s|%s|" % (hex(arg.avalue), arg.amemval)
            else:
                arg_line += "%d" % arg.avalue
            ret.append(arg_line)
        ret.append(") -> %d" % self.ret)
        return "\n".join(ret)

    def is_success(self):
        # type: () -> bool
        raise NotImplementedError()


class mixin_syscall_def_fd:
    O_ACCMODE = os.O_RDONLY | os.O_WRONLY | os.O_RDWR

    def __init__(self, *args, **kwargs):
        self.use_list = list()  # type: List[Union[syscall, mixin_syscall_use_fd]]

    def def_fd_add_use(self, fd_use):
        # type: (Union[syscall, mixin_syscall_use_fd]) -> int
        ret_val = len(self.use_list)
        self.use_list.append(fd_use)
        return ret_val

    def def_fd_get_path(self):
        # type: () -> path
        raise NotImplementedError()

    def def_fd_get_flags(self):
        # type: () -> bool
        raise NotImplementedError()

    def def_fd_flags_can_read(self):
        accmode = self.def_fd_get_flags() & self.O_ACCMODE
        return (accmode == os.O_RDONLY) or (accmode == os.O_RDWR)

    def def_fd_flags_can_write(self):
        accmode = self.def_fd_get_flags() & self.O_ACCMODE
        return (accmode == os.O_WRONLY) or (accmode == os.O_RDWR)


class mixin_syscall_use_fd:
    def __init__(self, *args, **kwargs):
        self.def_list = list()  # type: List[Union[syscall, mixin_syscall_def_fd]]

    def use_fd_add_def(self, fd_def):
        # type: (Union[syscall, mixin_syscall_def_fd]) -> int
        ret_val = len(self.def_list)
        self.def_list.append(fd_def)
        # fd_def.def_fd_add_use(self)
        return ret_val

    def use_fd_get_fds(self):
        # type: () -> List[int]
        raise NotImplementedError()


class mixin_syscall_has_path_args:
    def __init__(self, *args, **kwargs):
        pass

    def get_arg_paths(self):
        # type: () -> List[path]
        raise NotImplementedError()


def mixedomatic(cls):
    """ Mixed-in class decorator. """
    classinit = cls.__dict__.get('__init__')  # Possibly None.

    # Define an __init__ function for the class.
    def __init__(self, *args, **kwargs):
        # Call the __init__ functions of all the bases.
        for base in cls.__bases__:
            base.__init__(self, *args, **kwargs)
        # Also call any __init__ function that was in the class.
        if classinit:
            classinit(self, *args, **kwargs)

    # Make the local function the class's __init__.
    setattr(cls, '__init__', __init__)
    return cls
