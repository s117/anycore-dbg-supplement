from ..libsyscall.syscalls.factory import construct_syscall

i0 = (construct_syscall("sys_close", None, 0, 0, None, 0))
i1 = (construct_syscall("sys_openat", None, 0, 0, None, 0))
i2 = (construct_syscall("sys_accessat", None, 0, 0, None, 0))
i3 = (construct_syscall("sys_faccessat", None, 0, 0, None, 0))

print(i0)
print(i1)
print(i2)
print(i3)
