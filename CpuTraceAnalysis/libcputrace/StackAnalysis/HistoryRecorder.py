import libcputrace.StackAnalysis.CallStackTracker as CallStackTracker


class HistoryRecorder:
    def on_pop_frame(self, frame):
        # type: (CallStackTracker.CallStackTracker.StackFrame) -> None
        raise NotImplementedError()


class DummyHistoryRecorder(HistoryRecorder):
    def on_pop_frame(self, frame):
        pass
