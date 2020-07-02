from collections import deque
from typing import Deque, Optional, Generator, List

from lib.MachineCode.Instruction import Instruction
from lib.StackAnalysis.HistoryRecorder import HistoryRecorder, DummyHistoryRecorder
import lib.StackAnalysis.TraceCodePatternScanner as TraceCodePatternScanner

from lib.MachineCode.SymbolTable import SymbolTable
from lib.utils import strong_check, weak_check


class CallStackTracker:
    """
    Stack structure:
        -TOS-            [ -TOS- , ..... , -BOS-  ]
        CallFrame 3      [ Call 2, Call 1, Call 0 ]
        ExceptionFrame 2 [ Excp Vec ]
        CallFrame 1      [ Call 1, Call 0 ]
        CallFrame 0      [ Call 0 ]
        ResetFrame 0     [ Init Vec ]
        -BOS-
    Behavior:
        Function call, link type   - push a call frame, push a function call record to new frame
        Function call, unlink type - push a function call record to the current frame
        Function Ret               - pop the top call frame
        Exception                  - push a exception frame, push the exception entry to the new frame
        ExceptionRet               - keep popping the frame until an exception frame is popped
    """

    class Stack:
        def __init__(self):
            self.frame_stack = deque()  # type: Deque[CallStackTracker.StackFrame]

        def push_frame(self, f):
            # type: (CallStackTracker.StackFrame) -> None
            self.frame_stack.append(f)

        def pop_frame(self):
            # type: () -> CallStackTracker.StackFrame
            return self.frame_stack.pop()

        def peek_tos(self):
            # type: () -> CallStackTracker.StackFrame
            return self.frame_stack[-1]

        def size(self):
            return len(self.frame_stack)

    class StackFrame:
        def __init__(self, cycle_start, cycle_end, return_addr):
            # type: (int, Optional[int], int) -> None
            self.cycle_start = cycle_start
            self.cycle_end = cycle_end
            self.record_stack = deque()  # type: Deque[CallStackTracker.ActiveRecord]
            self.return_addr = return_addr

        def add_active_record(self, record):
            # type: (CallStackTracker.ActiveRecord) -> CallStackTracker.StackFrame
            self.record_stack.append(record)
            return self

        def end_frame(self, end_cycle):
            # type: (int) -> None
            self.cycle_end = end_cycle
            for r in self.record_stack:
                r.end_record(end_cycle)

        def check_return_address(self, actual_return_addr):
            # type: (Optional[int]) -> None
            strong_check(isinstance(self.return_addr, int))
            if not isinstance(actual_return_addr, int):
                return
            if self.return_addr >= 0 and actual_return_addr >= 0:
                weak_check(
                    actual_return_addr == self.return_addr,
                    "the core should goto the expected return address when a frame is popped"
                )

    class FunctionFrame(StackFrame):
        def __init__(self, cycle_start, cycle_end, return_addr):
            # type: (int, Optional[int], int) -> None
            super().__init__(cycle_start, cycle_end, return_addr)

    class ExceptionFrame(FunctionFrame):
        EXPECT_ERET_OFFSET = {
            # 0x0: None,  # MISALIGNED_FETCH,
            0x1: 0,  # FAULT_FETCH,
            0x2: Instruction.INSN_SIZE_BYTE,  # ILLEGAL_INSTRUCTION,
            # 0x3: None,  # PRIVILEGED_INSTRUCTION,
            0x4: 0,  # FP_DISABLED,
            0x6: Instruction.INSN_SIZE_BYTE,  # SYSCALL,
            0x7: Instruction.INSN_SIZE_BYTE,  # BREAKPOINT,
            # 0x8: None,  # MISALIGNED_LOAD,
            # 0x9: None,  # MISALIGNED_STORE,
            0xa: 0,  # FAULT_LOAD,
            0xb: 0,  # FAULT_STORE,
            # 0xc: 0,  # ACCELERATOR_DISABLED,
        }

        def __init__(self, cycle_start, cycle_end,
                     evec, ecause, epc, sr):
            # type: (int, Optional[int], int, int, int, int) -> None

            self.evec = evec
            self.ecause = ecause
            self.epc = epc
            self.sr = sr
            if ecause in self.EXPECT_ERET_OFFSET:
                return_addr = epc + self.EXPECT_ERET_OFFSET[ecause]
            else:
                return_addr = -1
            super().__init__(cycle_start, cycle_end, return_addr)

    class ResetFrame(FunctionFrame):
        def __init__(self, cycle_start, cycle_end, reset_vec):
            # type: (int, Optional[int], int) -> None
            super().__init__(cycle_start, cycle_end, -1)
            self.reset_vec = reset_vec

    class ActiveRecord:
        def __init__(self, cycle_start, cycle_end, frame):
            # type: (int, Optional[int], CallStackTracker.StackFrame) -> None
            self.cycle_start = cycle_start
            self.cycle_end = cycle_end
            self.frame = frame

        def end_record(self, end_cycle):
            self.cycle_end = end_cycle

        def __str__(self):
            return "%s - active from cycle %d to %d" % (type(self), self.cycle_start, self.cycle_end)

    class FunctionRecord(ActiveRecord):
        def __init__(self, cycle_start, cycle_end, frame,
                     callee_symbol, caller_symbol, caller_insn_addr):
            # type: (int, Optional[int], CallStackTracker.StackFrame, SymbolTable.Symbol, SymbolTable.Symbol, int) -> None
            super().__init__(cycle_start, cycle_end, frame)
            self.callee_symbol = callee_symbol
            self.caller_symbol = caller_symbol
            self.caller_insn_addr = caller_insn_addr

        def __str__(self):
            return "%s:%s @ %s, called by %s:%s @ %s" % (
                self.callee_symbol.symbol_name,
                SymbolTable.format_addr(self.callee_symbol.start_addr),
                self.callee_symbol.module_name,

                self.caller_symbol.symbol_name,
                SymbolTable.format_addr(self.caller_insn_addr),
                self.caller_symbol.module_name,
            )

    class ExceptionRecord(ActiveRecord):
        ECAUSE_STRING = {
            0x0: "MISALIGNED_FETCH",
            0x1: "FAULT_FETCH",
            0x2: "ILLEGAL_INSTRUCTION",
            0x3: "PRIVILEGED_INSTRUCTION",
            0x4: "FP_DISABLED",
            0x6: "SYSCALL",
            0x7: "BREAKPOINT",
            0x8: "MISALIGNED_LOAD",
            0x9: "MISALIGNED_STORE",
            0xa: "FAULT_LOAD",
            0xb: "FAULT_STORE",
            0xc: "ACCELERATOR_DISABLED"
        }

        @staticmethod
        def format_ecause(ecause):
            return (
                ("%s (0x%02X)" % (CallStackTracker.ExceptionRecord.ECAUSE_STRING[ecause], ecause))
                if ecause in CallStackTracker.ExceptionRecord.ECAUSE_STRING
                else "0x%02X" % ecause
            )

        def __init__(self, cycle_start, cycle_end, frame):
            # type: (int, Optional[int], CallStackTracker.ExceptionFrame) -> None
            super().__init__(cycle_start, cycle_end, frame)

        def __str__(self):
            ret_val = "Exception, cause %s, epc %s" % (
                self.format_ecause(self.frame.ecause),
                SymbolTable.format_addr(self.frame.epc)
            )

            return ret_val

    class ResetRecord(FunctionRecord):
        def __init__(self, cycle_start, cycle_end, frame,
                     callee_symbol):
            # type: (int, Optional[int], CallStackTracker.StackFrame, SymbolTable.Symbol) -> None
            super().__init__(cycle_start, cycle_end, frame, callee_symbol, None, -1)

        def __str__(self):
            ret_val = "%s:%s @ %s, called by Reset (reset vector %s)" % (
                self.callee_symbol.symbol_name,
                SymbolTable.format_addr(self.callee_symbol.start_addr),
                self.callee_symbol.module_name,
                SymbolTable.format_addr(self.frame.reset_vec)
            )

            return ret_val

    def __init__(self, scanner, history_recorder=None):
        # type: (TraceCodePatternScanner.TraceCodePatternScanner, HistoryRecorder) -> None
        self.scanner = scanner  # type: TraceCodePatternScanner.TraceCodePatternScanner
        self.frame_stack = CallStackTracker.Stack()
        if history_recorder:
            self.history_recorder = history_recorder
        else:
            self.history_recorder = DummyHistoryRecorder()

    def set_history_recorder(self, history_recorder):
        # type: (HistoryRecorder) -> None
        self.history_recorder = history_recorder

    def track_poweron_reset(self, cycle, trig_pc):
        new_frame = CallStackTracker.ResetFrame(cycle, None, trig_pc)
        self.frame_stack.push_frame(new_frame)
        reset_record = CallStackTracker.ResetRecord(cycle, None, new_frame,
                                                    self.scanner.get_symbol_by_addr(trig_pc))
        new_frame.add_active_record(reset_record)

    def track_func_call_link_type(self, cycle, addr_target, addr_return, trig_pc):
        # type: (int, int, int, int) -> None
        caller_symbol = self.scanner.get_symbol_by_addr(trig_pc)
        callee_symbol = self.scanner.get_symbol_by_addr(addr_target)

        weak_check(callee_symbol.start_addr == addr_target, "should never call into the middle of function")

        new_frame = CallStackTracker.FunctionFrame(cycle, None, addr_return)
        self.frame_stack.push_frame(new_frame)

        new_record = CallStackTracker.FunctionRecord(cycle, None, new_frame,
                                                     callee_symbol, caller_symbol, trig_pc)
        new_frame.add_active_record(new_record)

    def track_func_call_unlink_type(self, cycle, addr_target, trig_pc):
        # type: (int, int, int) -> None
        caller_symbol = self.scanner.get_symbol_by_addr(trig_pc)
        callee_symbol = self.scanner.get_symbol_by_addr(addr_target)

        weak_check(callee_symbol.start_addr == addr_target, "should never call into the middle of function")

        curr_tos_frame = self.frame_stack.peek_tos()
        new_record = CallStackTracker.FunctionRecord(cycle, None, curr_tos_frame,
                                                     callee_symbol, caller_symbol, trig_pc)
        curr_tos_frame.add_active_record(new_record)

    def track_func_return(self, cycle, addr_target, trig_pc):
        # type: (int, int, int) -> None
        popped_frame = self.frame_stack.pop_frame()
        popped_frame.end_frame(cycle)

        strong_check(
            isinstance(popped_frame, CallStackTracker.FunctionFrame),
            "RET instruction is popping a function frame"
        )

        popped_frame.check_return_address(addr_target)

        self.history_recorder.on_pop_frame(popped_frame)

    def track_exception(self, cycle, evec, ecause, epc, sr, trig_pc):
        # type: (int, int, int, int, int, int) -> None
        weak_check(trig_pc == epc, "EPC should set to the exception triggering instruction")

        new_frame = CallStackTracker.ExceptionFrame(cycle, None,
                                                    evec, ecause, epc, sr)
        self.frame_stack.push_frame(new_frame)

        new_frame.add_active_record(CallStackTracker.ExceptionRecord(cycle, None, new_frame))

    def track_exception_return(self, cycle, addr_target, trig_pc):
        # type: (int, Optional[int], int) -> None
        def check_is_program_loading():
            """
            This is a Proxy Kernel related heuristic
            """
            stack_backtrace = self.backtrack_stack(0)
            if stack_backtrace:
                top_record = stack_backtrace[0]

                return (
                        isinstance(top_record, CallStackTracker.FunctionRecord) and
                        top_record.callee_symbol.symbol_name == "pop_tf" and
                        top_record.caller_symbol.symbol_name == "boot"
                )
            else:
                return False

        create_program_start_frame = check_is_program_loading()

        while self.frame_stack.size() != 0:
            popped_frame = self.frame_stack.pop_frame()
            popped_frame.end_frame(cycle)

            self.history_recorder.on_pop_frame(popped_frame)

            if isinstance(popped_frame, CallStackTracker.ExceptionFrame):
                popped_frame.check_return_address(addr_target)
                break

        if create_program_start_frame:
            new_frame = CallStackTracker.FunctionFrame(cycle, None, -1)
            self.frame_stack.push_frame(new_frame)
            new_record = CallStackTracker.FunctionRecord(
                cycle, None, new_frame,
                self.scanner.get_symbol_by_addr(addr_target),
                self.scanner.get_symbol_by_addr(trig_pc),
                trig_pc
            )
            new_frame.add_active_record(new_record)

    def foreach_top_down(self):
        # type: () -> Generator[ActiveRecord]
        curr_frame_pos = self.frame_stack.size() - 1

        while curr_frame_pos >= 0:
            curr_frame = self.frame_stack.frame_stack[curr_frame_pos]
            curr_records = curr_frame.record_stack
            curr_records_pos = len(curr_records) - 1

            while curr_records_pos >= 0:
                curr_frame_rec = curr_records[curr_records_pos]
                curr_records_pos -= 1
                yield curr_frame_rec

            curr_frame_pos -= 1

    def describe_curr_call_stack(self):
        stack_desc = []
        for rec in self.foreach_top_down():
            stack_desc.append(str(rec))
        return "\n".join(stack_desc)

    def backtrack_stack(self, level):
        # type: (int) -> Optional[List[ActiveRecord]]
        strong_check(level >= 0)
        step_remain = level + 1
        ret_val = list()
        for rec in self.foreach_top_down():
            ret_val.append(rec)
            step_remain -= 1
            if step_remain == 0:
                break

        if step_remain == 0:
            return ret_val
        else:
            return None

    def finalize(self, cycle):
        while self.frame_stack.size() > 0:
            popped_frame = self.frame_stack.pop_frame()
            popped_frame.end_frame(cycle)
            self.history_recorder.on_pop_frame(popped_frame)
