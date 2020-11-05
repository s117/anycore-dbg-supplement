#!/usr/bin/env python3.8
# coding=utf8
import click

from .libcputrace.MachineCode.Objdump import get_objdump_content
from .libcputrace.StackAnalysis.CallStackTracker import CallStackTracker
from .libcputrace.StackAnalysis.Recorder.GoogleTraceEventFormatRecorder import GoogleTraceEventFormatRecorder
from .libcputrace.StackAnalysis.TraceCodePatternScanner import TraceCodePatternScanner

from .libcputrace.MachineCode.SymbolTable import SymbolTable
from .libcputrace.Trace.SimpleTraceFileReader import SimpleTraceFileReader


@click.command()
@click.argument('modules', nargs=-1, type=click.Path(exists=True))
@click.argument('trace_file', nargs=1, type=click.Path(exists=True))
@click.option("-o", "--output-filename", help="Override the default output filename (about_tracing.json)")
def main(modules, trace_file, output_filename):
    # load symbol
    if not output_filename:
        output_filename = "about_tracing.json"
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
    json_recorder = GoogleTraceEventFormatRecorder()
    tracker.set_history_recorder(json_recorder)
    scanner.set_tracker(tracker)

    # scan the trace
    print("Scanning the trace")
    scanner.scan()

    # output the result for visualization
    json_recorder.dump_json(output_filename)

    print("Done")

    return 0


if __name__ == '__main__':
    exit(main())
