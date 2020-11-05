#!/usr/bin/env python3.8
# coding=utf8

import sys

from .libcputrace.Trace.SimpleTraceFileReader import SimpleTraceFileReader


def main():
    if len(sys.argv) < 2:
        return -1
    trace_fileA = sys.argv[-1]

    # load trace
    print("Loading trace file '%s'" % trace_fileA)
    traceA = SimpleTraceFileReader(trace_fileA)

    iter_rng = traceA.size()

    expect_seq = 1

    for i in range(iter_rng):
        tr_ev_A = traceA.at(i)
        if tr_ev_A.seq != expect_seq:
            print("C/%d S/%d doesn't match expected %d" % (tr_ev_A.cycle, tr_ev_A.seq, expect_seq))
        expect_seq = tr_ev_A.seq + 1
    print("Last seq: %d" % (expect_seq - 1))
    return 0


if __name__ == '__main__':
    exit(main())
