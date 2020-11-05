#!/usr/bin/env python3
import re
import sys

header_regex = re.compile(
    r"^\s*Requesting target memory (\S+)"
    r"\s*\*\*\*\*\*\*\* Resetting core \*\*\*\*\*\*\*\*\*\*"
    r"\s*\*\*\*\*Initializing the processor system\*\*\*\*"
    r"\s*\*\*\*\*\*\*\* Resetting core \*\*\*\*\*\*\*\*\*\*"
    r"\s*\*\*\*\*\*\*\* Resetting core \*\*\*\*\*\*\*\*\*\*"
    r"\s*\*\*\*\*Initialization complete\*\*\*\*\n"
)

tail_regex = re.compile(
    r"("
    r"cycle = (\S+)\n"
    r"instret = (\S+)\n"
    r")?"
    r"\*\*\*\*\*\*\* Resetting core \*\*\*\*\*\*\*\*\*\*\s*$"
)


def main():
    ret_code = 0

    if len(sys.argv) != 2:
        print("Usage: %s [simout]" % sys.argv[0], file=sys.stderr)
        ret_code = -1
    else:
        with open(sys.argv[1], 'r') as fp_spike_out:
            spike_out = fp_spike_out.read()
            sim_out = spike_out

            head_match = header_regex.match(spike_out)
            if head_match:
                sim_out = sim_out[head_match.end():]
            else:
                print("Warning: No header match", file=sys.stderr)
                ret_code |= 1

            tail_match = tail_regex.search(sim_out)
            if tail_match:
                sim_out = sim_out[:tail_match.start()]
            else:
                print("Warning: No tail match", file=sys.stderr)
                ret_code |= 2
            print(sim_out, file=sys.stdout)

    sys.exit(ret_code)


if __name__ == '__main__':
    main()
