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
        def parse_foreach():
            split_trace_txt = self.trace_txt.split("\n\n")
            for trace_record in split_trace_txt:
                basic_info = (self.extract_basic_info(trace_record))
                if basic_info:
                    cycle, seq, pc, insn, asm = basic_info
                    extra_info = self.extract_extra_info(trace_record)
                    yield TraceEventInstRetired(cycle, seq, pc, insn, asm, extra_info)

        with open(trace_file_path, "r") as tf:
            self.trace_txt = tf.read()

        self.trace_event = [ev for ev in parse_foreach()]  # type: List[Union[TraceEventInstRetired]]

    def foreach(self):
        for idx, ev in enumerate(self.trace_event):
            yield idx, ev

    def at(self, i):
        # type: (int) -> Optional[TraceEventInstRetired]
        try:
            return self.trace_event[i]
        except IndexError:
            return None
