#!/usr/bin/env python3.8
# coding=utf8
import os
import shutil
import tempfile
import click

from .libcputrace.MachineCode.Objdump import get_objdump_content
from .libcputrace.StackAnalysis.CallStackTracker import CallStackTracker
from .libcputrace.StackAnalysis.Recorder.JsonHistoryRecorder import JsonHistoryRecorder
from .libcputrace.StackAnalysis.TraceCodePatternScanner import TraceCodePatternScanner

from .libcputrace.MachineCode.SymbolTable import SymbolTable
from .libcputrace.Trace.SimpleTraceFileReader import SimpleTraceFileReader
from .libcputrace.utils import xopen


# Copy the timeline frontend to a folder
def prepare_trace_vis_web_root(web_root):
    src_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "trace_vis")
    shutil.copytree(src_dir, web_root)


# Setup a temporary simple http server, then open URL in system default browser
def start_trace_vis_webserver(web_root, try_port=8080):
    from http.server import HTTPServer
    from http.server import SimpleHTTPRequestHandler

    server_class = HTTPServer
    handler_class = SimpleHTTPRequestHandler
    if not os.path.isdir(web_root):
        raise RuntimeError("Web root [%s] is not a dir!")
    if not os.access(web_root, os.R_OK):
        raise RuntimeError("Current user doesn't have the read permission on web root [%s]!")
    os.chdir(web_root)
    port = try_port

    while True:
        try:
            server_address = ('127.0.0.1', port)
            show_url = "http://localhost:%s/trace_view.html" % port
            httpd = server_class(server_address, handler_class)
            print("A temporary simple HTTP server will be held at %s:%s for viewing the result." % server_address)
            print("HTTP server is up with web root [%s]" % web_root)
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
    with tempfile.TemporaryDirectory() as tmp_web_root:
        trace_vis_root = os.path.join(tmp_web_root, "trace_vis")
        prepare_trace_vis_web_root(trace_vis_root)
        json_recorder.dump_json(os.path.join(trace_vis_root, "data_src.json"))
        start_trace_vis_webserver(trace_vis_root)

    print("Done")

    return 0


if __name__ == '__main__':
    exit(main())
