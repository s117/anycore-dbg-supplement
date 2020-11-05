from typing import List, Optional

from . import CallStackTracker

from ..MachineCode.Instruction import Instruction
from ..MachineCode.SymbolTable import SymbolTable
from ..Trace.SimpleTraceFileReader import SimpleTraceFileReader
from ..Trace.TraceEvent import TraceEventInstRetired
from ..utils import strong_check, weak_check


class TraceCodePatternScanner:
    INSN_SIZE_BYTE = Instruction.INSN_SIZE_BYTE

    class MachineCodePattern:
        def __init__(self, scanner):
            # type: (TraceCodePatternScanner) -> None
            self.scanner = scanner  # type: TraceCodePatternScanner

        def feed(self, ev_insn_retire):
            # type: (TraceEventInstRetired) -> None
            raise NotImplementedError()

    class Pattern_Reset(MachineCodePattern):
        def __init__(self, scanner, reset_vector=0x2000):
            # type: (TraceCodePatternScanner, int) -> None
            super().__init__(scanner)
            self.first_insn = True
            self.reset_vector = reset_vector

        def feed(self, ev_insn_retire):
            # type: (TraceEventInstRetired) -> None
            if self.first_insn and ev_insn_retire.pc == self.reset_vector:
                self.scanner.get_tracker().track_poweron_reset(ev_insn_retire.cycle, ev_insn_retire.pc)
                self.first_insn = False

    class Pattern_FuncCall(MachineCodePattern):
        def feed(self, ev_insn_retire):
            # type: (TraceEventInstRetired) -> None
            if ev_insn_retire.insn.op_code() in {Instruction.OP_JAL, Instruction.OP_JALR}:
                if ev_insn_retire.insn.rd() != 0:
                    # it is a link type function call
                    addr_ret = ev_insn_retire.pc + TraceCodePatternScanner.INSN_SIZE_BYTE
                    weak_check(
                        ev_insn_retire.extra_info["RD"][0] == addr_ret,
                        "RD should be set to the return address for JAL(R)"
                    )
                    self.scanner.get_tracker().track_func_call_link_type(
                        ev_insn_retire.cycle,
                        ev_insn_retire.extra_info["TAKEN_PC"][0],
                        addr_ret,
                        ev_insn_retire.pc
                    )
                else:
                    # it is an unlink type function call ONLY when the jump target is the entry of a function
                    jmp_target = ev_insn_retire.extra_info["TAKEN_PC"][0]
                    jmp_target_symbol = self.scanner.get_symtab().find_symbol_by_addr(
                        jmp_target
                    )  # type: SymbolTable.Symbol
                    if jmp_target_symbol and jmp_target == jmp_target_symbol.start_addr:
                        self.scanner.get_tracker().track_func_call_unlink_type(
                            ev_insn_retire.cycle,
                            ev_insn_retire.extra_info["TAKEN_PC"][0],
                            ev_insn_retire.pc
                        )

    class Pattern_FuncRet(MachineCodePattern):
        def feed(self, ev_insn_retire):
            # type: (TraceEventInstRetired) -> None
            if ev_insn_retire.insn.get_dism_op() == "ret":
                # it is a link type function call
                self.scanner.get_tracker().track_func_return(
                    ev_insn_retire.cycle,
                    ev_insn_retire.extra_info["TAKEN_PC"][0],
                    ev_insn_retire.pc
                )

    class Pattern_Int(MachineCodePattern):
        def feed(self, ev_insn_retire):
            # type: (TraceEventInstRetired) -> None
            if "EXCEPTION" in ev_insn_retire.extra_info:
                next_insn_retire_ev = self.scanner.peek_around_trace_event(1)
                weak_check(
                    not next_insn_retire_ev or next_insn_retire_ev.pc == ev_insn_retire.extra_info["EVEC"][0],
                    "core should fetch from EVEC when exception is raised"
                )

                self.scanner.get_tracker().track_exception(
                    ev_insn_retire.cycle,
                    ev_insn_retire.extra_info["EVEC"][0],
                    ev_insn_retire.extra_info["ECAUSE"][0],
                    ev_insn_retire.extra_info["EPC"][0],
                    ev_insn_retire.extra_info["SR"][0],
                    ev_insn_retire.pc
                )

    class Pattern_IntRet(MachineCodePattern):
        def feed(self, ev_insn_retire):
            # type: (TraceEventInstRetired) -> None
            if ev_insn_retire.insn.get_dism_op() == "sret" and "EXCEPTION" not in ev_insn_retire.extra_info:
                next_insn_retire_ev = self.scanner.peek_around_trace_event(1)
                self.scanner.get_tracker().track_exception_return(
                    ev_insn_retire.cycle,
                    next_insn_retire_ev.pc if next_insn_retire_ev else None,
                    ev_insn_retire.pc
                )

    def __init__(self, trace_reader, symtab):
        # type: (SimpleTraceFileReader, SymbolTable) -> None
        self.trace_reader = trace_reader
        self.symtab = symtab
        self.call_stack_tracker = None
        self.curr_scan_idx = 0

        self.patterns = []  # type: List[TraceCodePatternScanner.MachineCodePattern]
        self.register_pattern()

    def register_pattern(self):
        # type: () -> None
        self.patterns.append(TraceCodePatternScanner.Pattern_FuncCall(self))
        self.patterns.append(TraceCodePatternScanner.Pattern_FuncRet(self))
        self.patterns.append(TraceCodePatternScanner.Pattern_Int(self))
        self.patterns.append(TraceCodePatternScanner.Pattern_IntRet(self))
        self.patterns.append(TraceCodePatternScanner.Pattern_Reset(self))

    def scan(self):
        # type: () -> None
        total_trace_ev = self.trace_reader.size()

        for self.curr_scan_idx, ev in self.trace_reader.foreach():
            for pattern in self.patterns:
                weak_check(
                    isinstance(ev, TraceEventInstRetired),
                    "the trace should only have this type of trace event currently"
                )
                pattern.feed(ev)

            if self.curr_scan_idx & 0xffff == 0:
                print("Finished 0x%X/0x%X (%0.1f%%)" % (
                    self.curr_scan_idx, total_trace_ev, (float(self.curr_scan_idx) / total_trace_ev) * 100
                ))

        self.call_stack_tracker.finalize(self.trace_reader.at(-1).cycle)

    def peek_around_trace_event(self, n):
        # type: (int) -> Optional[TraceEventInstRetired]
        return self.trace_reader.at(self.curr_scan_idx + n)

    def get_trace_event_by_idx(self, idx):
        # type: (int) -> Optional[TraceEventInstRetired]
        return self.trace_reader.at(idx)

    def get_curr_scan_pos(self):
        # type: () -> int
        return self.curr_scan_idx

    def set_tracker(self, tracker):
        # type: (CallStackTracker.CallStackTracker) -> None
        self.call_stack_tracker = tracker

    def get_tracker(self):
        # type: () -> CallStackTracker.CallStackTracker
        return self.call_stack_tracker

    def get_symtab(self):
        # type: () -> SymbolTable
        return self.symtab

    def get_symbol_by_addr(self, addr):
        # type: (int) -> SymbolTable.Symbol
        if addr is None:
            return SymbolTable.Symbol("Unknown symbol", "Unknown", -1, -1)

        symbol = self.symtab.find_symbol_by_addr(addr)
        if not symbol:
            return SymbolTable.Symbol("Unknown symbol", "Unknown", addr, addr)
        else:
            return symbol
