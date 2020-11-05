import json
import yaml
import os
from collections import defaultdict

from ..CallStackTracker import CallStackTracker
from ..HistoryRecorder import HistoryRecorder


class JsonHistoryRecorder(HistoryRecorder):
    def __init__(self):
        self.record = list()
        self.ignored_function_call_list = defaultdict(set)
        self.init_ignore_list()

    def init_ignore_list(self):
        if not os.path.isfile("ignore_symbol.yaml"):
            return
        with open("ignore_symbol.yaml", 'r') as stream:
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
