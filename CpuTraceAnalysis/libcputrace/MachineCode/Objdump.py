import re
import tempfile
from enum import Enum, auto
from io import StringIO
from typing import Union, Generator, Optional

from .Instruction import Instruction
from .Label import Label
from ..utils import ShellCmdWrapper

# DEFAULT_OBJDUMP_PREFIX = "riscv64-unknown-elf-"
DEFAULT_OBJDUMP_PREFIX = "riscv64-unknown-linux-gnu-"


class InvalidObjdumpOutput(Exception):
    pass


class FailObjdumpInvoke(Exception):
    pass


def is_elf_file(file_path):
    # type: (str) -> bool
    with open(file_path, "rb") as fp:
        elf_magic = fp.read(4)
        return elf_magic == b"\x7f\x45\x4c\x46"


def dism_elf_with_objdump(file_path, objdump_prefix):
    # type: (str, str) -> str
    cmd = [objdump_prefix + "objdump", "-S", file_path]
    tmp_stdout = tempfile.TemporaryFile(mode="r+")
    tmp_stderr = tempfile.TemporaryFile(mode="r+")

    cmd_wrapper = ShellCmdWrapper(
        cmd, stdin_pipe=None, stdout_pipe=tmp_stdout, stderr_pipe=tmp_stderr
    )
    cmd_wrapper.launch_cmd()
    cmd_wrapper.join()
    ret_code = cmd_wrapper.get_ret_code()
    tmp_stdout.seek(0)
    tmp_stderr.seek(0)
    stdout_output, stderr_output = tmp_stdout.read(), tmp_stderr.read()

    if ret_code != 0:
        raise FailObjdumpInvoke(
            "Fail to analysis module '%s' using command:\n"
            "  %s\n\n"
            "Return code: %d\n\n"
            "Stdout:\n"
            "%s"
            "\n\n"
            "Stderr:\n"
            "%s" % (
                file_path,
                " ".join(cmd),
                ret_code,
                stdout_output,
                stderr_output

            )
        )

    return stdout_output


def get_objdump_content(file_path):
    # type: (str) -> str
    if is_elf_file(file_path):
        return dism_elf_with_objdump(file_path, DEFAULT_OBJDUMP_PREFIX)
    else:
        with open(file_path, "r") as fp:
            return fp.read()


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
            raise InvalidObjdumpOutput("Not a valid OBJDUMP -S output")

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
        while True:
            curr_line_text = self.content_buf.readline()
            if not curr_line_text:
                break
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
        while True:
            step_st = self.step()
            if self.StepStatus.ST_EOF == step_st:
                break
            if step_st == self.StepStatus.ST_NEW_INSN:
                yield self.get_curr_insn()
            else:
                yield self.get_current_label()
