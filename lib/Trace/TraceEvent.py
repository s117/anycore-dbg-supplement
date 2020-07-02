from typing import Dict, Any

from lib.MachineCode.Instruction import Instruction


class TraceEventInstRetired:
    def __init__(self, cycle, seq, pc, insn, dism, extra_info):
        # type: (int, int, int, int, str, Dict[str, Any]) -> None
        self.cycle = cycle
        self.seq = seq
        self.pc = pc
        self.insn = Instruction(pc, insn, dism.strip())
        self.extra_info = extra_info
