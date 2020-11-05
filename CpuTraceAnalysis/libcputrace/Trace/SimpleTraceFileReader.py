import re
import gzip

from typing import Optional, Tuple, Dict, List, Union

from .TraceEvent import TraceEventInstRetired
from ..utils import strong_check, weak_check


class SimpleTraceFileReader:
    regex_extra_info = re.compile(r"^\s+(\S+)\s+(0x[\dabcdef]+)$", re.MULTILINE)
    regex_header = re.compile(r"^S/(\d+)\s+C/(\d+)\s+I/(\d+)\s+PC/0x([\dabcdef]+)\s+\(0x([\dabcdef]+)\)\s+(.+)$",
                              re.MULTILINE)

    @staticmethod
    def extract_basic_info(trace_txt):
        # type: (str) -> Optional[Tuple[int, int, int, int, int, str]]
        match_txt = trace_txt.strip()
        if not match_txt:
            return None
        match = SimpleTraceFileReader.regex_header.match(match_txt)
        if match:
            return (
                int(match.group(1)), int(match.group(2)), int(match.group(3)), int(match.group(4), 16),
                int(match.group(5), 16),
                match.group(6)
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
        self.tr_ev_offset_idx = list()  # type: List[Tuple[int, int]]

        if trace_file_path.endswith(".gz"):
            self.trace_file_fp = gzip.open(trace_file_path, "rt", encoding="ascii")
        else:
            self.trace_file_fp = open(trace_file_path, "r")

        trace_content = self.trace_file_fp.read()
        self.trace_content = trace_content

        curr_tr_ev_begin = 0
        curr_tr_ev_end = trace_content.find(TRACE_EV_SEPARATOR, curr_tr_ev_begin)

        while curr_tr_ev_end > 0:
            if trace_content[curr_tr_ev_begin:curr_tr_ev_end].strip():
                self.tr_ev_offset_idx.append(
                    (curr_tr_ev_begin, curr_tr_ev_end - curr_tr_ev_begin)
                )
            curr_tr_ev_begin = curr_tr_ev_end + TRACE_EV_SEPARATOR_LEN
            curr_tr_ev_end = trace_content.find(TRACE_EV_SEPARATOR, curr_tr_ev_begin)

        leftover = trace_content[curr_tr_ev_begin:].rstrip()
        if leftover:
            self.tr_ev_offset_idx.append(
                (curr_tr_ev_begin, len(leftover))
            )
        # print("INDEX DONE")
        # sys.exit(0)

        # self.tr_ev_offset_idx = [ev for ev in parse_foreach()]  # type: List[Union[TraceEventInstRetired]]

    def __del__(self):
        if self.trace_file_fp:
            self.trace_file_fp.close()

    def foreach(self):
        for idx in range(len(self.tr_ev_offset_idx)):
            yield idx, self.at(idx)

    def at(self, i):
        # type: (int) -> Optional[TraceEventInstRetired]
        try:
            tr_ev_data_offset, tr_ev_data_len = self.tr_ev_offset_idx[i]
        except IndexError:
            return None

        tr_ev_data = self.trace_content[tr_ev_data_offset:tr_ev_data_offset + tr_ev_data_len]
        basic_info = (self.extract_basic_info(tr_ev_data))
        if basic_info:
            seq, cycle, instret, pc, insn, asm = basic_info
            extra_info = self.extract_extra_info(tr_ev_data)
            return TraceEventInstRetired(seq, cycle, instret, pc, insn, asm, extra_info)

    def size(self):
        return len(self.tr_ev_offset_idx)

    def earliest_cycle(self):
        if self.size():
            return self.at(0).cycle
        else:
            return 0
