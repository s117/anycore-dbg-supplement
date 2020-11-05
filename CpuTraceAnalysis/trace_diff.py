#!/usr/bin/env python3.8
# coding=utf8
import sys
from typing import Optional, List, Dict, Any

from .libcputrace.MachineCode.Objdump import get_objdump_content
from .libcputrace.MachineCode.SymbolTable import SymbolTable
from .libcputrace.Trace.SimpleTraceFileReader import SimpleTraceFileReader
from .libcputrace.utils import weak_check, strong_check


def print_usage():
    print(
        "Usage: \n" +
        "%s [objdump dism file list] <trace_fileA> <trace_fileB>" % sys.argv[0],
        file=sys.stderr
    )


def get_module_objdump_output():
    pass


def main():
    if len(sys.argv) < 3:
        print_usage()
        return -1
    trace_fileA = sys.argv[-1]
    trace_fileB = sys.argv[-2]
    modules = sys.argv[1:-2]

    def extra_info_cross_checking(_a, _b, _diff_info_list):
        # type: (Dict[str, Any], Dict[str, Any], List[str]) -> None
        allowed_missing_keys = {"INV_FETCH"}

        def _chk(__a, __b, __na, __nb, __cmp_val):
            # type: (Dict[str, Any], Dict[str, Any], str, str, bool) -> None
            for k in __a.keys():
                if k not in __b:
                    if k not in allowed_missing_keys:
                        _diff_info_list.append(
                            "%s has extra info %s but %s don't" % (
                                __na, k, __nb
                            )
                        )
                else:
                    if __cmp_val and __a[k] != __b[k]:
                        _diff_info_list.append(
                            "Value difference: %s[%s] = %s, %s[%s] = %s" % (
                                __na, k, __a[k], __nb, k, __b[k]
                            )
                        )

        _chk(_a, _b, "A", "B", True)
        _chk(_b, _a, "B", "A", False)

        pass

    def get_sym_name(offset):
        sym = symtab.find_symbol_by_addr(offset)
        if sym:
            return str(sym)
        else:
            return "Unknown symbol"

    # load symbol
    symtab = SymbolTable()
    for module_path in modules:
        print("Loading symbol from '%s'" % module_path)
        objdump_content = get_objdump_content(module_path)
        symtab.add_symbol_from_objdump_dism(objdump_content)

    # load trace
    print("Loading trace file A '%s'" % trace_fileA)
    traceA = SimpleTraceFileReader(trace_fileA)
    print("Loading trace file B '%s'" % trace_fileB)
    traceB = SimpleTraceFileReader(trace_fileB)
    if traceA.size() != traceB.size():
        print("Warning: Trace A and Trace B has different number of trace event")

    iter_rng = min(traceA.size(), traceB.size())

    diff_info_list = []  # type: List[str]

    for i in range(iter_rng):
        tr_ev_A = traceA.at(i)
        tr_ev_B = traceB.at(i)
        strong_check(tr_ev_A.seq == tr_ev_B.seq, "SeqNo must start from the same, and continuous.")
        if tr_ev_A.pc != tr_ev_B.pc:
            diff_info_list.append(
                "Different PC, A PC=%08x %s in %s, B PC=%08x %s in %s" % (
                    tr_ev_A.pc, tr_ev_A.insn.objdump_dism, get_sym_name(tr_ev_A.pc),
                    tr_ev_B.pc, tr_ev_A.insn.objdump_dism, get_sym_name(tr_ev_B.pc)
                )
            )

        if tr_ev_A.insn.insn != tr_ev_B.insn.insn:
            diff_info_list.append("Different instruction")

        extra_info_cross_checking(tr_ev_A.extra_info, tr_ev_B.extra_info, diff_info_list)

        if diff_info_list:
            print("%s at S/%d:" % (
                "Multiple difference" if len(diff_info_list) > 1 else "One issue",
                i + 1
            ))
            if tr_ev_A.pc == tr_ev_B.pc:
                print(
                    "PC=%08x, %s in %s" % (
                        tr_ev_A.pc, tr_ev_A.insn.objdump_dism, get_sym_name(tr_ev_A.pc)
                    )
                )
            for ti, t in enumerate(diff_info_list, start=1):
                print("\t%d: %s" % (ti, t))
            break
    if diff_info_list:
        print("Trace A and B are different")
    else:
        print("Trace A and B are same")
    return -1 if diff_info_list else 0


if __name__ == '__main__':
    exit(main())
