import base64

from pyparsing import *


class StraceInputParser:
    list_arg_type_num = {
        "uint64_t": "int 64",
        "int64_t": "int 64",
        "ptr_in_t": "ptr input",
        "ptr_out_t": "ptr for output",
        "fd_t": "file descriptor"
    }

    list_arg_type_strptr = {
        "path_in_t": "path str for input",
        "path_out_t": "path str for output",
        "str_in_t": "str for input",
        "str_out_t": "str for output",
    }

    # syntax we don't want to see in the final parse tree
    LBRACKET, RBRACKET, LPAREN, RPAREN, EQ, VBAR = map(Suppress, "[]()=|")
    ARROW = Suppress("->")
    ident = Word(alphas, alphanums + "_")
    integer = Regex(r"[+-]?\d+")
    hexinteger = Regex(r"0x[0-9a-fA-F]+")
    base64_val = Regex(r"(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?")

    integer.setParseAction(lambda toks: int(toks[0], base=10))
    hexinteger.setParseAction(lambda toks: int(toks[0], base=16))
    base64_val.setParseAction(lambda toks: base64.b64decode(toks[0]).decode('ascii'))

    arg_type_num = oneOf(t for t in list_arg_type_num)
    arg_type_strptr = oneOf(t for t in list_arg_type_strptr)

    num_value = (hexinteger | integer)("arg_val")
    strptr_value = (hexinteger("arg_val") + VBAR + base64_val("arg_memval") + VBAR)

    scall_arg_num_type = Group(arg_type_num("arg_type") + ident("arg_name") + EQ + num_value)
    scall_arg_strptr_type = Group(arg_type_strptr("arg_type") + ident("arg_name") + EQ + strptr_value)

    scall_args = scall_arg_num_type | scall_arg_strptr_type

    scall_record = LBRACKET + integer("syscall_id") + RBRACKET + ident("syscall_name") + LPAREN + \
                   Group(ZeroOrMore(scall_args))("syscall_args") + \
                   RPAREN + ARROW + integer("ret_code")

    scall_traces = scall_record | StringEnd()

    @staticmethod
    def on_parse_fail(s, loc, expr, err):
        raise ParseFatalException(s, loc, str(err))

    scall_traces.setFailAction(
        on_parse_fail
    )

    @classmethod
    def parse(cls, strace_str):
        # find instances of enums ignoring other syntax
        for item in cls.scall_traces.scanString(strace_str):
            yield item

    @classmethod
    def stringify(cls, s):
        ret = ["[%d] %s (" % (s.syscall_id, s.syscall_name)]
        for arg in s.syscall_args:
            arg_line = "  %s %s = " % (arg.arg_type, arg.arg_name)
            if arg.arg_type in cls.list_arg_type_strptr:
                arg_line += "%s|%s|" % (hex(arg.arg_val), arg.arg_memval)
            else:
                arg_line += "%d" % arg.arg_val
            ret.append(arg_line)
        ret.append(") -> %d" % s.ret_code)
        return "\n".join(ret)
