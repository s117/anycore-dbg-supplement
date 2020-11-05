import bisect
import os
import sys
from collections import defaultdict
from functools import partial
from io import StringIO
from typing import List, Optional, Dict, Tuple

from .Instruction import Instruction
from .Label import Label
from .Objdump import ObjdumpDismOutputParser
from ..utils import strong_check, weak_check


class SymbolTable:
    class Symbol:
        def __init__(self, symbol_name, module_name, start_addr, end_addr):
            # type: (str, str, int, int) -> None
            self.symbol_name = symbol_name
            self.module_name = module_name
            self.start_addr = start_addr
            self.end_addr = end_addr

        def __str__(self):
            return "<%s:%s>, 0x%08X - 0x%08X" % (self.module_name, self.symbol_name, self.start_addr, self.end_addr)

    def __init__(self):
        # type: () -> None
        self.symtab = list()  # type: List[SymbolTable.Symbol]
        self.aux_bisect_idx_arr = list()  # type: List[int]

    def find_symbol_by_addr(self, addr):
        # type: (int) -> Optional[SymbolTable.Symbol]
        # return record format: [start, end, module_name, symbol_name]
        if not self.aux_bisect_idx_arr:
            return None
        symtab_idx = bisect.bisect_right(self.aux_bisect_idx_arr, addr)
        symtab_idx = max(symtab_idx - 1, 0)

        if self.symtab[symtab_idx].start_addr <= addr <= self.symtab[symtab_idx].end_addr:
            return self.symtab[symtab_idx]
        else:
            return None

    @staticmethod
    def format_addr(addr):
        # type: (int) -> str
        if addr is None:
            strong_check(False)
        elif addr < 0:
            return "N/A"
        else:
            return "0x%08X" % addr

    def add_symbol(self, module_name, symbol_info):
        # type: (str, Dict[str, Tuple[int, int]]) -> None
        # accept record format: [start, end, module_name, symbol_name]
        self.symtab.extend(
            map(
                lambda item: SymbolTable.Symbol(item[0], module_name, item[1][0], item[1][1]),
                symbol_info.items()
            )
        )

        self.symtab = sorted(self.symtab, key=lambda t: t.start_addr)
        self.aux_bisect_idx_arr = list(map(lambda i: i.start_addr, self.symtab))

        self._check_symbol_overlapping()

    def add_symbol_from_objdump_dism(self, dism_content):
        # type: (str) -> None

        parser = ObjdumpDismOutputParser(dism_content)

        module_name = os.path.basename(parser.module_name)
        name_conflict_counters = defaultdict(partial(int, 0))

        # format: symbol_name -> [start, end]
        fn_sym_table = dict()  # type: Dict[str, Tuple[int, int]]
        curr_tracking_name = None
        for x in parser.foreach():
            if isinstance(x, Instruction):
                assert curr_tracking_name
                # print(x.get_dism_op())
                fn_sym_table[curr_tracking_name] = (
                    fn_sym_table[curr_tracking_name][0],
                    x.offset
                )
            elif isinstance(x, Label):
                if x.name in fn_sym_table:

                    name_conflict_counters[x.name] += 1
                    curr_tracking_name = x.name + " (%d)" % name_conflict_counters[x.name]
                    print("Warning: duplicated symbol detected: %s, rename the new symbol to %s" % (
                        x.name, curr_tracking_name
                    ))
                else:
                    curr_tracking_name = x.name

                fn_sym_table[curr_tracking_name] = (x.offset, x.offset)

        self.add_symbol(module_name, fn_sym_table)

    def _check_symbol_overlapping(self):
        # type: () -> None
        def is_overlapping(sym1, sym2):
            # type: (SymbolTable.Symbol, SymbolTable.Symbol) -> bool
            return max(sym1.start_addr, sym2.start_addr) <= min(sym1.end_addr, sym2.end_addr)

        for s in self.symtab:
            if s.start_addr > s.end_addr:
                raise ValueError("Symbol %s (%s) has a invalid value range %08X - %08X (range_low > range_high)" % (
                    s.symbol_name, s.module_name, s.start_addr, s.end_addr
                ))
        for i in range(len(self.symtab)):
            for j in range(i + 1, len(self.symtab)):
                if is_overlapping(self.symtab[i], self.symtab[j]):
                    print(
                        "Warning: symbol %s (%s) and %s (%s) overlapping" % (
                            self.symtab[i].symbol_name, self.symtab[i].module_name,
                            self.symtab[j].symbol_name, self.symtab[j].module_name
                        ), file=sys.stderr
                    )
