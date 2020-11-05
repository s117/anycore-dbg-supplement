from typing import Optional, Dict, List, Any

_FACTORY_REGISTER = None  # type: Optional[Dict]
_DEFAULT_FACTORY = None


def _init_register():
    from . import syscall
    from . import sys_exit
    from . import sys_read
    from . import sys_pread
    from . import sys_write
    from . import sys_pwrite
    from . import sys_close
    from . import sys_lseek
    from . import sys_fstat
    from . import sys_fcntl
    from . import sys_ftruncate
    from . import sys_lstat
    from . import sys_openat
    from . import sys_fstatat
    from . import sys_faccessat
    from . import sys_linkat
    from . import sys_unlinkat
    from . import sys_mkdirat
    from . import sys_getcwd
    from . import sys_getmainvars
    from . import sys_chdir
    from . import sys_getdents64
    from . import sys_getrandom
    from . import sys_renameat2
    global _DEFAULT_FACTORY
    global _FACTORY_REGISTER
    _DEFAULT_FACTORY = syscall.syscall
    _FACTORY_REGISTER = {
        "sys_exit": sys_exit.sys_exit,
        "sys_read": sys_read.sys_read,
        "sys_pread": sys_pread.sys_pread,
        "sys_write": sys_write.sys_write,
        "sys_pwrite": sys_pwrite.sys_pwrite,
        "sys_close": sys_close.sys_close,
        "sys_lseek": sys_lseek.sys_lseek,
        "sys_fstat": sys_fstat.sys_fstat,
        "sys_fcntl": sys_fcntl.sys_fcntl,
        "sys_ftruncate": sys_ftruncate.sys_ftruncate,
        "sys_lstat": sys_lstat.sys_lstat,
        "sys_openat": sys_openat.sys_openat,
        "sys_fstatat": sys_fstatat.sys_fstatat,
        "sys_faccessat": sys_faccessat.sys_faccessat,
        "sys_linkat": sys_linkat.sys_linkat,
        "sys_unlinkat": sys_unlinkat.sys_unlinkat,
        "sys_mkdirat": sys_mkdirat.sys_mkdirat,
        "sys_getcwd": sys_getcwd.sys_getcwd,
        "sys_getmainvars": sys_getmainvars.sys_getmainvars,
        "sys_chdir": sys_chdir.sys_chdir,
        "sys_getdents64": sys_getdents64.sys_getdents64,
        "sys_getrandom": sys_getrandom.sys_getrandom,
        "sys_renameat2": sys_renameat2.sys_renameat2,
    }


def construct_syscall(name, args, ret, syscall_id, at_cwd, seq_no):
    # type: (str, List, int, int, str, int) -> Any
    if _FACTORY_REGISTER is None:
        _init_register()
    return _FACTORY_REGISTER.get(name, _DEFAULT_FACTORY)(name, args, ret, syscall_id, at_cwd, seq_no)
