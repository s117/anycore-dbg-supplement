from typing import Dict, Any

from ..MachineCode.Instruction import Instruction


class TraceEventInstRetired:
    def __init__(self, seq, cycle, instret, pc, insn, dism, extra_info):
        # type: (int, int, int, int, int, str, Dict[str, Any]) -> None
        self.seq = seq
        self.cycle = cycle
        self.instret = instret
        self.pc = pc
        self.insn = Instruction(pc, insn, dism.strip())
        self.extra_info = extra_info
