import re
from enum import Enum, auto
from io import StringIO
from typing import Union, TextIO, Generator, Optional

from lib.MachineCode.Instruction import Instruction
from lib.MachineCode.Label import Label


class ObjdumpDismOutputParser:
    reg_objdump_label_line_pattern = re.compile(r"^\s*([0-9a-fA-F]{1,16})\s*<(\S+)>\s*:\s*$", re.MULTILINE)
    reg_objdump_asm_line_pattern = re.compile(r"^\s*([0-9a-fA-F]{1,16}):\s*([0-9a-fA-F]{8})\s+(.+)$", re.MULTILINE)
    reg_objdump_meta_pattern = re.compile(r"^(.+):\s+file format (.+)$", re.MULTILINE)

    @staticmethod
    def _parse_objdump_asm_line(line):
        # type: (str) -> Optional[Instruction]
        matches = ObjdumpDismOutputParser.reg_objdump_asm_line_pattern.finditer(line)

        for matchNum, match in enumerate(matches, start=1):
            return Instruction(
                int(match.group(1), 16),
                int(match.group(2), 16),
                match.group(3)
            )

        return None

    @staticmethod
    def _parse_objdump_label_line(line):
        # type: (str) -> Optional[Label]
        matches = ObjdumpDismOutputParser.reg_objdump_label_line_pattern.finditer(line)

        for matchNum, match in enumerate(matches, start=1):
            return Label(
                int(match.group(1), 16),
                match.group(2)
            )

        return None

    @staticmethod
    def _parse_objdump_meta(file_content):
        # type: (str) -> (str, str)
        matches = ObjdumpDismOutputParser.reg_objdump_meta_pattern.finditer(file_content)

        for matchNum, match in enumerate(matches, start=1):
            return match.group(1), match.group(2)

        return None, None

    class StepStatus(Enum):
        ST_NEW_INSN = auto()
        ST_NEW_LABEL = auto()
        ST_EOF = auto()

    def __init__(self, dism_content):
        # type: (str) -> None
        self.content_buf = StringIO(dism_content)

        self.module_name, self.module_bin_format = self._parse_objdump_meta(dism_content)
        if not self.module_name:
            raise ValueError("Not a valid OBJDUMP -S output")

        self.curr_label = None
        self.curr_insn = None

        self.parse_seq = (
            self._parse_objdump_asm_line,
            self._parse_objdump_label_line
        )

    def __del__(self):
        # type: () -> None
        self.content_buf.close()

    def get_current_label(self):
        # type: () -> Label
        return self.curr_label

    def get_curr_insn(self):
        # type: () -> Instruction
        return self.curr_insn

    def step(self):
        # type: () -> StepStatus
        while curr_line_text := self.content_buf.readline():
            for pf in self.parse_seq:
                parse_result = pf(curr_line_text)
                if isinstance(parse_result, Instruction):
                    self.curr_insn = parse_result
                    return self.StepStatus.ST_NEW_INSN
                elif isinstance(parse_result, Label):
                    self.curr_label = parse_result
                    return self.StepStatus.ST_NEW_LABEL

        return self.StepStatus.ST_EOF

    def foreach(self):
        # type: () -> Generator[Union[Instruction, Label]]
        while self.StepStatus.ST_EOF != (step_st := self.step()):
            if step_st == self.StepStatus.ST_NEW_INSN:
                yield self.get_curr_insn()
            else:
                yield self.get_current_label()
