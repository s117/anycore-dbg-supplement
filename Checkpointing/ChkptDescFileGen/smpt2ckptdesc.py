#!/usr/bin/env python3
import gzip
import os
import sys
from functools import reduce
from operator import add
from typing import List


def read_simpoints(path):
    # type: (str) -> List[int]
    with open(path, "r") as smpt_fp:
        idx = 0
        ret_val = []  # type: List[int]
        for line in smpt_fp:
            if line.strip():
                line_split = line.split(' ')
                line_smpt = int(line_split[0].strip())
                line_idx = int(line_split[1].strip())
                if line_idx != idx:
                    raise RuntimeError("Corrupt input file: " + os.path.join(os.getcwd(), "simpoints"))
                idx += 1
                ret_val.append(line_smpt)

        return ret_val


def read_weights(path):
    # type: (str) -> List[float]
    with open(path, "r") as smpt_fp:
        idx = 0
        ret_val = []  # type: List[float]
        for line in smpt_fp:
            if line.strip():
                line_split = line.split(' ')
                line_weight = float(line_split[0].strip())
                line_idx = int(line_split[1].strip())
                if line_idx != idx:
                    raise RuntimeError("Corrupt input file: " + os.path.join(os.getcwd(), "weights"))
                idx += 1
                ret_val.append(line_weight)

        return ret_val


def get_exact_skip_count_using_pc_count(pcfreq_vec_path, smpt_weight_pos_pairs):
    if pcfreq_vec_path.endswith(".gz"):
        fvec_fp = gzip.open(pcfreq_vec_path)
    else:
        fvec_fp = open(pcfreq_vec_path)

    assert len(smpt_weight_pos_pairs) > 0
    smpt_weight_pos_pairs_sorted_by_pos = sorted(smpt_weight_pos_pairs, key=lambda i: i[1])
    count = 0
    smpt_weight_pos_skipcount_pairs = []
    curr_idx = 0

    for fvec_sn, fvec_line in enumerate(fvec_fp):
        if fvec_sn == smpt_weight_pos_pairs_sorted_by_pos[curr_idx][1]:
            smpt_weight_pos_skipcount_pairs.append(
                (
                    smpt_weight_pos_pairs_sorted_by_pos[curr_idx][0],
                    smpt_weight_pos_pairs_sorted_by_pos[curr_idx][1],
                    count
                )
            )
            curr_idx += 1
            if curr_idx >= len(smpt_weight_pos_pairs_sorted_by_pos):
                break

        if isinstance(fvec_line, bytes):
            fvec_line = fvec_line.decode("ascii")
        fvec_line = fvec_line.strip()
        if fvec_line:
            fvec = fvec_line.split(" ")
            if len(fvec) < 3 or fvec[1] != ":":
                print("Invalid PC frequency vector input file", file=sys.stderr)
                return -1
            count += int(fvec[0])

    assert len(smpt_weight_pos_skipcount_pairs) == len(smpt_weight_pos_pairs)
    return smpt_weight_pos_skipcount_pairs


def main():
    def print_help():
        print("Usage:", file=sys.stderr)
        print(
            "  %s <simpoint_interval> <checkpoint_basename> <path_to_simpoint> <path_to_weights> [path_to_pcfreq_vec]" %
            sys.argv[0],
            file=sys.stderr)

        print("Examples:")
        print("  %s 100000000 456.hmmer_ref ./simpoints ./weights" % sys.argv[0], file=sys.stderr)
        print("  %s 100000000 641.leela_s_ref /tmp/spike_sim/simpoints /tmp/spike_sim/weights" % sys.argv[0],
              file=sys.stderr)

    if len(sys.argv) != 5 and len(sys.argv) != 6:
        print_help()
        sys.exit(-1)

    try:
        simpoint_interval = int(sys.argv[1])
    except ValueError:
        print("Invalid SimPoint Interval: %s" % sys.argv[1], file=sys.stderr)
        print_help()
        sys.exit(-1)
    ckpt_basename = sys.argv[2]
    simpoints_path = sys.argv[3]
    weights_path = sys.argv[4]
    if len(sys.argv) == 6:
        pcfreq_vec_path = sys.argv[5]
    else:
        pcfreq_vec_path = None

    for c in ckpt_basename:
        if not (c.isalnum() or c == '-' or c == '_' or c == '.'):
            print("Invalid checkpoint name: " + ckpt_basename + "\n" +
                  "  (a valid checkpoint name can only contain char, digit, '-', '_', '.')", file=sys.stderr)
            sys.exit(-1)
    try:
        simpoints = read_simpoints(simpoints_path)
        weights = read_weights(weights_path)
    except FileNotFoundError as ef:
        # print("Fail to load simpoint data: %s" % str(ef), file=sys.stderr)
        sys.exit(-1)

    if len(simpoints) != len(weights):
        raise RuntimeError("Input 'weights' and 'simpoints' not match")

    smpt_weight_pos_pairs = sorted(list(zip(weights, simpoints)), key=lambda i: i[1])

    if pcfreq_vec_path:
        smpt_weight_pos_skipcount_pairs = get_exact_skip_count_using_pc_count(pcfreq_vec_path, smpt_weight_pos_pairs)

        for sim_weight, sim_sn, sim_skipcount in smpt_weight_pos_skipcount_pairs:
            print("%s.%d.%0.2f:%d" % (
                ckpt_basename, sim_sn, sim_weight, sim_skipcount
            ))
    else:
        for sim_weight, sim_sn in smpt_weight_pos_pairs:
            print("%s.%d.%0.2f:%d" % (
                ckpt_basename, sim_sn, sim_weight, sim_sn * simpoint_interval
            ))
    print("%2d - %3.2f%%\t%s" % (len(weights), int(reduce(add, weights) * 10000) / 100.0, ckpt_basename),
          file=sys.stderr)

    sys.exit(0)


if __name__ == '__main__':
    main()
