#!/usr/bin/env python3

# chkpt format: HTIF | 0xbaadbeefdeadbeef | memory | 0xdeadbeefbaadbeef | proc

import click
import gzip
import sys
from typing import Tuple, Iterable, Dict, Any, List, Callable, Optional, Set

SYSTEM_ENCODING = 'ascii'
TARGET_XLEN = 64
TARGET_ENDIAN = 'little'
HOST_XLEN = 64
HOST_ENDIAN = 'little'


class htif_stream_event_handler:
    def on_read_target_mem(self, addr, size, data):
        # type: (int, int, bytes) -> None
        print("Read %d bytes @ 0x%08x: %s" % (size, addr, " ".join(map(lambda b: hex(b), data))))

    def on_write_target_mem(self, addr, size, data):
        # type: (int, int, bytes) -> None
        print("Write %d bytes @ 0x%08x: %s" % (size, addr, " ".join(map(lambda b: hex(b), data))))

    def on_mod_core_scr(self, coreid, regno, old_val, new_val):
        # type: (int, int, int, int) -> None
        print("Mod Core CSR: core %d, reg %d, oldval %d, newval %d" % (coreid, regno, old_val, new_val))

    def on_mod_sys_scr(self, regno, val):
        # type: (int, int) -> None
        print("Mod Sys CSR: reg %d, val %d" % (regno, val))

    def on_end(self):
        print("HTIF restoration stream ended")


class syscall_info_extractor(htif_stream_event_handler):
    delegated_syscall = {
        93: {"name": "sys_exit", "args": [
            "reg_t code"
        ]},
        63: {"name": "sys_read", "args": [
            "fd_t fd", "ptr_t pbuf", "size_t len",
        ]},
        64: {"name": "sys_write", "args": [
            "fd_t fd", "ptr_t pbuf", "size_t len"
        ]},
        56: {"name": "sys_openat", "args": [
            "dirfd_t dirfd", "cstr_path_t pname", "size_t len", "reg_t flags", "reg_t mode"
        ]},
        57: {"name": "sys_close", "args": [
            "fd_t fd"
        ]},
        80: {"name": "sys_fstat", "args": [
            "fd_t fd", "ptr_t pbuf"
        ]},
        62: {"name": "sys_lseek", "args": [
            "fd_t fd", "size_t offset", "reg_t dir"
        ]},
        1039: {"name": "sys_lstat", "args": [
            "cstr_path_t pname", "size_t len", "ptr_t pbuf"
        ]},
        79: {"name": "sys_fstatat", "args": [
            "dirfd_t dirfd", "cstr_path_t pname", "size_t len", "ptr_t pbuf", "reg_t flags"
        ]},
        48: {"name": "sys_faccessat", "args": [
            "dirfd_t dirfd", "cstr_path_t pname", "size_t len", "reg_t mode"
        ]},
        25: {"name": "sys_fcntl", "args": [
            "fd_t fd", "reg_t cmd", "reg_t arg"
        ]},
        37: {"name": "sys_linkat", "args": [
            "dirfd_t odirfd", "cstr_path_t poname", "reg_t olen", "dirfd_t ndirfd", "cstr_path_t pnname", "reg_t nlen",
            "reg_t flags"
        ]},
        35: {"name": "sys_unlinkat", "args": [
            "dirfd_t dirfd", "cstr_path_t pname", "size_t len", "reg_t flags"
        ]},
        34: {"name": "sys_mkdirat", "args": [
            "dirfd_t dirfd", "cstr_path_t pname", "size_t len", "reg_t mode"
        ]},
        17: {"name": "sys_getcwd", "args": [
            "ptr_t pbuf", "size_t len"
        ]},
        67: {"name": "sys_pread", "args": [
            "fd_t fd", "ptr_t pbuf", "size_t len", "reg_t off"
        ]},
        68: {"name": "sys_pwrite", "args": [
            "fd_t fd", "ptr_t pbuf", "size_t len", "reg_t off"
        ]},
        2011: {"name": "sys_getmainvars", "args": [
            "ptr_t pbuf", "reg_t limit"
        ]},
        46: {"name": "sys_ftruncate", "args": [
            "fd_t fd", "size_t len"
        ]},
        49: {"name": "sys_chdir", "args": [
            "cstr_path_t path", "size_t len"
        ]},
        61: {"name": "sys_getdents64", "args": [
            "fd_t fd", "ptr_t dirbuf", "reg_t count"
        ]},
        278: {"name": "sys_getrandom", "args": [
            "ptr_t buf", "size_t buflen", "reg_t flags"
        ]},
        276: {"name": "sys_renameat2", "args": [
            "dirfd_t odirfd", "cstr_path_t popath", "size_t olen", "dirfd_t ndirfd", "cstr_path_t pnpath", "reg_t nlen",
            "reg_t flags"
        ]},
    }

    CSR_ID_TO_HOST = 0x51e & 0x1f
    CSR_ID_FROM_HOST = 0x51f & 0x1f

    class args_typedef:
        type_list = {  # typename: (size in byte, signed, ptr)
            "reg_t": (TARGET_XLEN >> 3, False, False),
            "sreg_t": (TARGET_XLEN >> 3, True, False),
            "fd_t": (TARGET_XLEN >> 3, True, False),
            "dirfd_t": (TARGET_XLEN >> 3, True, False),
            "size_t": (TARGET_XLEN >> 3, False, False),
            "ssize_t": (TARGET_XLEN >> 3, True, False),
            "ptr_t": (TARGET_XLEN >> 3, False, True),
            "cstr_path_t": (TARGET_XLEN >> 3, False, True),
            "cstr_t": (TARGET_XLEN >> 3, False, True),
            "int64_t": (8, True, False),
            "uint64_t": (8, False, False),
            "int32_t": (4, True, False),
            "uint32_t": (4, False, False),
            "int16_t": (2, True, False),
            "uint16_t": (2, False, False),
            "int8_t": (1, True, False),
            "uint8_t": (1, False, False),
        }

        @classmethod
        def type_check(cls, t):
            # type: (str) -> None
            if t[0] == "*":
                t_base = cls.base_ptr_type(t)
            else:
                t_base = t
            if t_base not in cls.type_list:
                raise ValueError("Unrecognized type: %s" % t)

        @classmethod
        def sizeof(cls, t):
            # type: (str) -> int
            return cls.type_list[t][0]

        @classmethod
        def is_signed(cls, t):
            # type: (str) -> bool
            return cls.type_list[t][1]

        @classmethod
        def is_ptr(cls, t):
            # type: (str) -> bool
            return cls.type_list[t][2]

        @classmethod
        def is_str(cls, t):
            # type: (str) -> bool
            return t == "cstr_path_t" or t == "cstr_t"

        @classmethod
        def deref_ptr_type(cls, t):
            # type: (str) -> str
            if not cls.is_ptr(t):
                raise ValueError("%s is not a ptr type hence cannot be dereferenced" % t)
            return "*" + t

        @classmethod
        def base_ptr_type(cls, t):
            # type: (str) -> str
            if t[0] == "*":
                return t[1:]
            else:
                return t

        @classmethod
        def _unpack_int(cls, t, v):
            # type: (str, bytes) -> Any
            def unpack_int(_dat, _size, _signed):
                # type: (bytes, int, bool) -> int
                assert len(_dat) >= _size
                return int.from_bytes(_dat[:_size], byteorder=HOST_ENDIAN, signed=_signed)

            return unpack_int(v, cls.sizeof(t), cls.is_signed(t))

        @classmethod
        def _unpack_star_cstr(cls, v, encoding=SYSTEM_ENCODING):
            # type: (bytes, str) -> str
            return v.split(b'\0', 1)[0].decode(encoding)

        @classmethod
        def _unpack_star_ptr(cls, v):
            # type: (bytes) -> bytes
            return v  # just return the raw data sequence

        @classmethod
        def unpack(cls, t, v):
            # type: (str, bytes) -> Any
            cls.type_check(t)
            if t[0] == '*':
                t_base = cls.base_ptr_type(t)
                if not cls.is_ptr(t_base):
                    raise ValueError("Cannot dereference a non-ptr type %s" % t_base)
                if t_base == "cstr_path_t" or t_base == "cstr_t":
                    return "%s" % cls._unpack_star_cstr(v)
                elif t_base == "ptr_t":
                    return cls._unpack_star_ptr(v)
            else:
                return cls._unpack_int(t, v)

        @classmethod
        def format(cls, t, uv):
            # type: (str, Any) -> str
            cls.type_check(t)
            if uv is None:
                return "?"
            if t[0] == '*':
                t_base = cls.base_ptr_type(t)
                if not cls.is_ptr(t_base):
                    raise ValueError("Cannot dereference a non-ptr type %s" % t_base)
                if t_base == "cstr_path_t" or t_base == "cstr_t":
                    assert isinstance(uv, str)
                    return "\"%s\"" % uv
                elif t_base == "ptr_t":
                    assert isinstance(uv, bytes)
                    return "[%s]" % ", ".join(map(lambda i: hex(i), uv))
            else:
                assert isinstance(uv, int)
                if cls.is_ptr(t):
                    return "&0x%016X" % uv
                elif t in {"reg_t", "sreg_t"}:
                    return hex(uv)
                elif t in {"dirfd_t"}:
                    return "AT_FDCWD" if uv == -100 else str(uv)
                else:
                    return str(uv)

    class mem_access_watcher:
        def __init__(self):
            self.watching_rd_addr = dict()  # type: Dict[int, Tuple[str, Callable[[str, int, bytes], None]]]
            self.watching_wr_addr = dict()  # type: Dict[int, Tuple[str, Callable[[str, int, bytes], None]]]

        def test_hit(self, access_addr, access_size, watch_set):
            # type: (int, int, Dict[int, Any]) -> Optional[(int, int)]
            for addr in watch_set:
                if access_addr <= addr <= access_addr + access_size:
                    return addr, addr - access_addr
            return None

        def on_rd(self, addr, data):
            # type: (int, bytes) -> None
            hit_result = self.test_hit(addr, len(data), self.watching_rd_addr)
            if hit_result:
                hit_addr, hit_offset = hit_result
                type_def, observed_cb = self.watching_rd_addr.pop(hit_addr)
                observed_cb(type_def, hit_addr, data[hit_offset:])

        def on_wr(self, addr, data):
            # type: (int, bytes) -> None
            hit_result = self.test_hit(addr, len(data), self.watching_wr_addr)
            if hit_result:
                hit_addr, hit_offset = hit_result
                type_def, observed_cb = self.watching_wr_addr.pop(hit_addr)
                observed_cb(type_def, hit_addr, data[hit_offset:])

        def watch_addr(self, addr, type_def, is_read, observed_cb):
            # type: (int, str, bool, Callable[[str, int, bytes], None]) -> None
            if is_read:
                target_set = self.watching_rd_addr
            else:
                target_set = self.watching_wr_addr

            target_set[addr] = (type_def, observed_cb)

        def reset(self):
            self.watching_rd_addr = dict()
            self.watching_wr_addr = dict()

    def __init__(self):
        self.addr_watcher = syscall_info_extractor.mem_access_watcher()
        self.curr_syscall_coreid = None
        self.curr_syscall_id = None
        self.curr_syscall_ret_val = None
        self.curr_syscall_desc = None
        self.curr_syscall_resolved_value = dict()  # type: Dict[str, str]

    def reset(self):
        self.addr_watcher.reset()
        self.curr_syscall_coreid = None
        self.curr_syscall_id = None
        self.curr_syscall_ret_val = None
        self.curr_syscall_desc = None
        self.curr_syscall_resolved_value = dict()  # type: Dict[str]

    def start_new_syscall_resolving(self, coreid, magic_mem_ptr):
        self.reset()

        def on_indirect_ptr_arg_resolved(arg_desc, addr, data):
            arg_type, arg_name = arg_desc.split()
            assert arg_desc[0] == "*"
            self.curr_syscall_resolved_value[arg_desc] = syscall_info_extractor.args_typedef.unpack(
                arg_type, data
            )

        def on_magic_mem_ptr_resolved(type_def, addr, data):
            # type: (str, int, bytes) -> None
            assert len(data) == 8 * 8

            self.curr_syscall_id = syscall_info_extractor.args_typedef.unpack("uint64_t", data[0:8])
            if self.curr_syscall_id in self.delegated_syscall:

                self.curr_syscall_desc = self.delegated_syscall[self.curr_syscall_id]

                for arg_pos, arg_desc in enumerate(self.curr_syscall_desc["args"], start=1):

                    arg_type, arg_name = arg_desc.split()
                    arg_raw_bytes = data[arg_pos << 3: (arg_pos << 3) + 8]

                    if arg_type == "cstr_path_t" or arg_type == "cstr_t":
                        baseaddr = syscall_info_extractor.args_typedef.unpack(arg_type, arg_raw_bytes)
                        self.curr_syscall_resolved_value[arg_desc] = syscall_info_extractor.args_typedef.unpack(
                            arg_type, arg_raw_bytes
                        )
                        self.addr_watcher.watch_addr(baseaddr, "*" + arg_desc, True, on_indirect_ptr_arg_resolved)
                    else:
                        self.curr_syscall_resolved_value[arg_desc] = syscall_info_extractor.args_typedef.unpack(
                            arg_type, arg_raw_bytes
                        )

        def on_return_value_resolved(type_def, addr, data):
            assert len(data) >= 8
            self.curr_syscall_ret_val = syscall_info_extractor.args_typedef.unpack("sreg_t", data[0:8])

        self.curr_syscall_coreid = coreid
        self.addr_watcher.watch_addr(magic_mem_ptr, "ptr_t[8] magic_mem", is_read=True,
                                     observed_cb=on_magic_mem_ptr_resolved)
        self.addr_watcher.watch_addr(magic_mem_ptr, "ptr_t[8] magic_mem", is_read=False,
                                     observed_cb=on_return_value_resolved)

    def finish_syscall_resolving(self):
        def generate_arg_list_str():
            formatted_arg_strs = []
            for arg in self.curr_syscall_desc["args"]:
                arg_type, arg_name = arg.split()
                arg_raw_value = self.curr_syscall_resolved_value.get(arg, None)
                if self.args_typedef.is_ptr(arg_type):
                    arg_ptr_deref_raw_value = self.curr_syscall_resolved_value.get("*" + arg, None)
                    if arg_ptr_deref_raw_value:
                        arg_str = "%s: %s @ %s" % (
                            arg_name,
                            self.args_typedef.format("*" + arg_type, arg_ptr_deref_raw_value),
                            self.args_typedef.format(arg_type, arg_raw_value)
                        )
                    else:
                        arg_str = "%s: %s" % (
                            arg_name,
                            self.args_typedef.format(arg_type, arg_raw_value)
                        )
                else:
                    arg_str = "%s: %s" % (
                        arg_name,
                        self.args_typedef.format(arg_type, arg_raw_value)
                    )
                formatted_arg_strs.append(arg_str)
            return formatted_arg_strs

        if self.curr_syscall_desc:
            syscall_name = self.curr_syscall_desc["name"]
            arg_list = ", ".join(generate_arg_list_str())
            print("%s(%s) = %s" % (syscall_name, arg_list, self.curr_syscall_ret_val))
        else:
            print("syscall_%s, returned %s" % (self.curr_syscall_id, self.curr_syscall_ret_val))
        self.on_syscall_detected()

    def on_syscall_detected(self):
        pass

    def on_read_target_mem(self, addr, size, data):
        # type: (int, int, bytes) -> None
        # super().on_read_target_mem(addr, size, data)
        self.addr_watcher.on_rd(addr, data)

    def on_write_target_mem(self, addr, size, data):
        # type: (int, int, bytes) -> None
        # super().on_write_target_mem(addr, size, data)
        self.addr_watcher.on_wr(addr, data)

    def on_mod_core_scr(self, coreid, regno, old_val, new_val):
        # type: (int, int, int, int) -> None
        # super().on_mod_core_scr(coreid, regno, old_val, new_val)
        if regno == syscall_info_extractor.CSR_ID_TO_HOST:
            htif_device_id = old_val >> 56
            if htif_device_id == htif_stream_reader.HTIF_DEVICE_ID_SYSCALL_PROXY:
                self.start_new_syscall_resolving(coreid, old_val)
        elif regno == syscall_info_extractor.CSR_ID_FROM_HOST:
            if old_val == 0 and new_val == 1:
                self.finish_syscall_resolving()

    def on_mod_sys_scr(self, regno, val):
        # type: (int, int) -> None
        # super().on_mod_sys_scr(regno, val)
        pass

    def on_end(self):
        # type: () -> None
        super().on_end()


class htif_stream_reader:
    HTIF_DEVICE_ID_SYSCALL_PROXY = 0
    HTIF_DATA_ALIGN = 8

    def __init__(self, path, handler):
        # type: (str, htif_stream_event_handler) -> None
        self.htif_stream_fp = gzip.open(path, "rb")
        self.curr_lineno = 0
        self.ev_handler = handler

    def expect_nextline(self):
        pos = self.htif_stream_fp.tell()
        newline = self.htif_stream_fp.readline().strip()
        self.curr_lineno += 1
        while not newline:
            if pos == self.htif_stream_fp.tell():
                raise ValueError("HTIF stream ended earlier than expect")
            pos = self.htif_stream_fp.tell()
            newline = self.htif_stream_fp.readline().strip()
            self.curr_lineno += 1

        return newline.decode("ascii")

    def run_parse(self):
        def convert_uint64_literals_to_bytes(_data_literals):
            # type: (Iterable[str]) -> bytes
            return b''.join(
                map(
                    lambda i: i.to_bytes(8, byteorder=HOST_ENDIAN),
                    map(
                        lambda l: int(l),
                        _data_literals
                    )
                )
            )

        while True:
            token_list = self.expect_nextline().split()
            htif_ev_name = token_list[0]

            if htif_ev_name == "MOD_SCR":
                assert len(token_list) == 5
                coreid = int(token_list[1])
                regno = int(token_list[2])
                old_val = int(token_list[3])
                new_val = int(token_list[4])
                if coreid == 0xFFFFF:
                    self.ev_handler.on_mod_sys_scr(regno, old_val)
                else:
                    self.ev_handler.on_mod_core_scr(coreid, regno, old_val, new_val)
            elif htif_ev_name == "READ_MEM" or htif_ev_name == "WRITE_MEM":
                assert len(token_list) == 3
                addr = int(token_list[1]) * htif_stream_reader.HTIF_DATA_ALIGN
                size = int(token_list[2]) * 8
                data_literals = self.expect_nextline().split()
                data = convert_uint64_literals_to_bytes(data_literals)
                assert len(data) == size
                if htif_ev_name == "READ_MEM":
                    self.ev_handler.on_read_target_mem(addr, size, data)
                else:
                    self.ev_handler.on_write_target_mem(addr, size, data)
            elif htif_ev_name == "END_HTIF_CHECKPOINT":
                assert len(token_list) == 4
                self.ev_handler.on_end()
                break
            else:
                raise ValueError("Unknown token %s" % token_list[0])


@click.command()
@click.argument("checkpoint", type=click.Path(exists=True, dir_okay=False, file_okay=True))
def main(checkpoint):
    htif_reader = htif_stream_reader(checkpoint, syscall_info_extractor())
    htif_reader.run_parse()


if __name__ == '__main__':
    main()
