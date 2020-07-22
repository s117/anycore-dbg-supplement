import re
from typing import Optional, Tuple, Dict, List, Union

from lib.Trace.TraceEvent import TraceEventInstRetired
from lib.utils import strong_check, weak_check


class SimpleTraceFileReader:
    regex_extra_info = re.compile(r"^\s+(\S+)\s+(0x[\dabcdef]+)$", re.MULTILINE)
    regex_header = re.compile(r"^C/(\d+)\s+S/(\d+)\s+PC/0x([\dabcdef]+)\s+\(0x([\dabcdef]+)\)\s+(.+)$", re.MULTILINE)

    @staticmethod
    def extract_basic_info(trace_txt):
        # type: (str) -> Optional[Tuple[int, int, int, int, str]]
        match_txt = trace_txt.strip()
        if not match_txt:
            return None
        match = SimpleTraceFileReader.regex_header.match(match_txt)
        if match:
            return (
                int(match.group(1)), int(match.group(2)), int(match.group(3), 16), int(match.group(4), 16),
                match.group(5)
            )
        else:
            raise ValueError("Invalid trace content: " + trace_txt)

    @staticmethod
    def extract_extra_info(trace_txt):
        # type: (str) -> Dict[str, Tuple]
        matches = SimpleTraceFileReader.regex_extra_info.finditer(trace_txt)
        extra_info = dict()
        for match in matches:
            if "/" in match.group(1):
                strong_check(match.group(1).count("/") == 1, "(trace format) only one '/' is allowed in the extra key")
                k1, k2 = match.group(1).split("/")
                extra_info[k1] = (int(match.group(2), 16), k2)
            else:
                k = match.group(1)
                extra_info[k] = (int(match.group(2), 16),)

        return extra_info

    def __init__(self, trace_file_path):
        # type: (str) -> None
        TRACE_EV_SEPARATOR = "\n\n"
        TRACE_EV_SEPARATOR_LEN = len(TRACE_EV_SEPARATOR)

        # format: [(offset, len)]
        self.trev_offset_idx = list()  # type: List[Tuple[int, int]]

        self.trace_file_fp = open(trace_file_path, "r")

        trace_content = self.trace_file_fp.read()

        curr_trev_begin = 0
        curr_trev_end = trace_content.find(TRACE_EV_SEPARATOR, curr_trev_begin)

        while curr_trev_end > 0:
            if trace_content[curr_trev_begin:curr_trev_end].strip():
                self.trev_offset_idx.append(
                    (curr_trev_begin, curr_trev_end - curr_trev_begin)
                )
            curr_trev_begin = curr_trev_end + TRACE_EV_SEPARATOR_LEN
            curr_trev_end = trace_content.find(TRACE_EV_SEPARATOR, curr_trev_begin)

        leftover = trace_content[curr_trev_begin:].rstrip()
        if leftover:
            self.trev_offset_idx.append(
                (curr_trev_begin, len(leftover))
            )
        print("INDEX DONE")
        # sys.exit(0)

        # self.trev_offset_idx = [ev for ev in parse_foreach()]  # type: List[Union[TraceEventInstRetired]]

    def __del__(self):
        if self.trace_file_fp:
            self.trace_file_fp.close()

    def foreach(self):
        for idx in range(len(self.trev_offset_idx)):
            yield idx, self.at(idx)

    def at(self, i):
        # type: (int) -> Optional[TraceEventInstRetired]
        try:
            trev_data_offset, trev_data_len = self.trev_offset_idx[i]
        except IndexError:
            return None

        self.trace_file_fp.seek(trev_data_offset)
        trev_data = self.trace_file_fp.read(trev_data_len)
        basic_info = (self.extract_basic_info(trev_data))
        if basic_info:
            cycle, seq, pc, insn, asm = basic_info
            extra_info = self.extract_extra_info(trev_data)
            return TraceEventInstRetired(cycle, seq, pc, insn, asm, extra_info)

    def size(self):
        return len(self.trev_offset_idx)
