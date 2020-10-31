#!/usr/bin/env python3.8
# coding=utf8
import json
import os
import sys
from collections import defaultdict

import click

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
        for k, v in ignore_dict.items():
            for vi in v:
                self.ignored_function_call_list[k].add(vi)

    def on_pop_frame(self, frame):
        # type: (CallStackTracker.StackFrame) -> None
        while len(frame.record_stack) != 0:
            record = frame.record_stack.pop()
            if (
                    isinstance(record, CallStackTracker.FunctionRecord) and
                    (
                            record.callee_symbol.symbol_name in
                            self.ignored_function_call_list[record.callee_symbol.module_name]
                    )
            ):
                continue

            self.record.append({
                "content": str(record),
                "start": record.cycle_start,
                "end": record.cycle_end,
                "type": "%s" % type(record).__name__
            })

    def dump_json(self, json_path):
        with open(json_path, "w") as fp:
            json.dump(self.record, fp)


def show_result(try_port=8080):
    from http.server import HTTPServer
    from http.server import SimpleHTTPRequestHandler

    server_class = HTTPServer
    handler_class = SimpleHTTPRequestHandler

    os.chdir(TRACE_VIS_DIR)
    port = try_port

    while True:
        try:
            server_address = ('127.0.0.1', port)
            show_url = "http://localhost:%s/trace_view.html" % port
            httpd = server_class(server_address, handler_class)
            print("A temporary simple HTTP server will be held at %s:%s for viewing the result." % server_address)
            xopen(show_url)
            print("A browser should opened now showing the result.")
            print("Manually open %s if not." % show_url)
            print("")
            httpd.serve_forever()
        except OSError as oe:
            if oe.errno == 98:
                port += 1
                continue
            else:
                raise oe
        except KeyboardInterrupt:
            return
        else:
            break


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
    json_recorder.dump_json(TRACE_VIS_DIR + "/data_src.json")

    # held a simple http server, open URL in system default browser
    print("Done")
    show_result()

    return 0


if __name__ == '__main__':
    exit(main())
