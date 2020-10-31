#!/usr/bin/env python3.8
# coding=utf8
import json
import os
import sys
import click

from collections import defaultdict

from libcputrace.MachineCode.Objdump import get_objdump_content
from libcputrace.StackAnalysis.CallStackTracker import CallStackTracker
from libcputrace.StackAnalysis.TraceCodePatternScanner import TraceCodePatternScanner
from libcputrace.StackAnalysis.HistoryRecorder import HistoryRecorder

from libcputrace.MachineCode.SymbolTable import SymbolTable
from libcputrace.Trace.SimpleTraceFileReader import SimpleTraceFileReader
from libcputrace.utils import xopen

TRACE_VIS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "trace_vis")


class JsonHistoryRecorder(HistoryRecorder):
    def __init__(self):
        self.record = list()
        self.ignored_function_call_list = defaultdict(set)
        self.init_ignore_list()

    def init_ignore_list(self):
        import yaml

        with open(os.path.join(os.path.dirname(__file__), "ignore_symbol.yaml"), 'r') as stream:
            try:
                ignore_dict = yaml.load(stream, Loader=yaml.SafeLoader)
            except yaml.YAMLError as exc:
                print(exc)
                exit(1)
        if ignore_dict:
            for k, v in ignore_dict.items():
                for vi in v:
                    self.ignored_function_call_list[k].add(vi)

    def on_pop_frame(self, frame):
        # type: (CallStackTracker.StackFrame) -> None
        while len(frame.record_stack) != 0:
            record = frame.record_stack.popleft()
            if (
                    isinstance(record, CallStackTracker.FunctionRecord) and
                    (
                            record.callee_symbol.symbol_name in
                            self.ignored_function_call_list[record.callee_symbol.module_name]
                    )
            ):
                continue

            self.record.append({
                "name": str(record),
                "ph": "X",
                "ts": record.cycle_start,
                "dur": record.cycle_end - record.cycle_start,
                "pid": 0,
                "tid": 0,
                "args": {
                    "type": "%s" % type(record).__name__
                }
            })

    def dump_json(self, json_path):
        with open(json_path, "w") as fp:
            json.dump(self.record, fp)


def get_module_objdump_output():
    pass


@click.command()
@click.argument('modules', nargs=-1, type=click.Path(exists=True))
@click.argument('trace_file', nargs=1, type=click.Path(exists=True))
def main(modules, trace_file):
    # load symbol
    symtab = SymbolTable()
    for module_path in modules:
        print("Loading symbol from '%s'" % module_path)
        objdump_content = get_objdump_content(module_path)
        symtab.add_symbol_from_objdump_dism(objdump_content)

    # load trace
    print("Loading trace file '%s'" % trace_file)
    trace = SimpleTraceFileReader(trace_file)

    # setup the trace scanner
    scanner = TraceCodePatternScanner(trace, symtab)
    tracker = CallStackTracker(scanner)
    json_recorder = JsonHistoryRecorder()
    tracker.set_history_recorder(json_recorder)
    scanner.set_tracker(tracker)

    # scan the trace
    print("Scanning the trace")
    scanner.scan()

    # output the result for visualization
    json_recorder.dump_json("about_tracing.json")

    # held a simple http server, open URL in system default browser
    print("Done")

    return 0


if __name__ == '__main__':
    exit(main())
