from typing import Optional
import os
import signal
import subprocess
from typing import IO, List
import logging


def xopen(filepath):
    # type: (str) -> None
    import subprocess, os, platform
    if platform.system() == 'Darwin':  # macOS
        subprocess.call(('open', filepath))
    elif platform.system() == 'Windows':  # Windows
        os.startfile(filepath)
    else:  # linux variants
        subprocess.call(('xdg-open', filepath))


def weak_check(b, purpose=None):
    # type: (bool, Optional[str]) -> None
    if not b:
        import inspect
        import sys
        call_stack = inspect.stack()
        caller_info = call_stack[1]
        warning_msg = [
            "Warning: weak check failed.",
            "Purpose of this check: %s" % purpose if purpose else "",
            "File \"%s\", line %d, in %s:" % (caller_info.filename, caller_info.lineno, caller_info.function)
        ]
        warning_msg.extend(caller_info.code_context)

        print("\n".join(warning_msg), file=sys.stderr)


def strong_check(b, purpose=None):
    # type: (bool, Optional[str]) -> None
    if not b:
        import inspect
        import sys
        call_stack = inspect.stack()
        caller_info = call_stack[1]
        warning_msg = [
            "Fatal: strong check failed:",
            "Purpose of this check: %s" % purpose if purpose else "",
            "File \"%s\", line %d, in %s:" % (caller_info.filename, caller_info.lineno, caller_info.function)
        ]
        warning_msg.extend(caller_info.code_context)

        raise RuntimeError("\n".join(warning_msg))


class ProcessStuckError(Exception):
    pass


def open_output_log(stdout_path, stderr_path):
    stdout_fp = open(stdout_path, "wb")
    stderr_fp = open(stderr_path, "wb")
    return stdout_fp, stderr_fp


def close_output_log(stdout, stderr):
    stdout.flush()
    stderr.flush()
    stdout.close()
    stderr.close()


def test_output_update(stdout: IO, stderr: IO):
    old_sout_pos, old_serr_pos = stdout.tell(), stderr.tell()
    stdout.seek(os.SEEK_END)
    stderr.seek(os.SEEK_END)
    cur_sout_pos, cur_serr_pos = stdout.tell(), stderr.tell()
    return old_sout_pos != cur_sout_pos or old_serr_pos != cur_serr_pos


def wait_proc(proc, timeout):
    try:
        proc.wait(timeout)
    except subprocess.TimeoutExpired:
        return False
    except KeyboardInterrupt:
        stop_subprocess(proc)
        raise
    return True


def stop_subprocess(proc):
    # Try quit the subprocess elegant first, give it 10 sec to quit
    logging.warning("Trying to terminate process %s with SIGINT" % proc.args)
    proc.send_signal(signal.SIGINT)
    if not wait_proc(proc, 10):
        # More aggressive, give it 10 sec
        logging.warning("SIGINT no response for 10sec, trying SIGTERM")
        proc.terminate()
        if not wait_proc(proc, 10):
            # Kill it, give it 10 sec
            logging.warning("SIGTERM no response for 10sec, trying SIGKILL")
            proc.kill()
            if not wait_proc(proc, 10):
                # Give it up after 30 sec try, report error
                raise RuntimeError("Cannot stop subprocess")


def test_and_create_dir(path):
    if not os.path.exists(path):
        os.makedirs(path)
    elif not os.path.isdir(path):
        raise RuntimeError("Fail to create dir %s: file already exist and is not a dir" % path)


class ShellCmdWrapper:

    def __init__(self, args, stdout_pipe=None, stderr_pipe=None, stdin_pipe=None, cwd=None):
        # type: (List[str], Optional[IO], Optional[IO], Optional[IO], str) -> None
        self.args = args
        self.stdin_pipe = stdin_pipe
        self.stdout_pipe, self.stderr_pipe = stdout_pipe, stderr_pipe
        self.cwd = cwd
        self.process_hndl = None  # type: Optional[subprocess.Popen]

    def launch_cmd(self):
        if self.process_hndl:
            return
        pipe_stdin, pipe_stdout, pipe_stderr = self.stdin_pipe, self.stdout_pipe, self.stderr_pipe

        args = self.args

        analysis_proc = subprocess.Popen(
            args=args,
            close_fds=False,
            stdin=pipe_stdin, stdout=pipe_stdout, stderr=pipe_stderr,
            cwd=self.cwd
        )
        self.process_hndl = analysis_proc

    def is_running(self):
        if self.process_hndl:
            return self.process_hndl.poll() is None
        else:
            return False

    def stop_process(self):
        if self.process_hndl and self.is_running():
            stop_subprocess(self.process_hndl)

    def output_updated(self):
        if not self.stdout_pipe or not self.stderr_pipe:
            raise ValueError("Provides a valid STDOUT and STDERR pipe for output update detection")
        return test_output_update(self.stdout_pipe, self.stderr_pipe)

    def wait(self, timeout=None):
        # return True if process is finished
        if self.process_hndl:
            return wait_proc(self.process_hndl, timeout)

    def join(self):
        if self.process_hndl:
            self.process_hndl.wait()

    def wait_with_freeze_detection(self, min_output_freeze_time):
        # return: is stuck
        if not self.process_hndl:
            return False

        if not self.is_running():
            return False

        while True:
            proc_finished = self.wait(min_output_freeze_time)
            if proc_finished:
                break

            stuck = self.output_updated()
            if stuck:
                return True
        return False

    def get_ret_code(self):
        if self.process_hndl:
            return self.process_hndl.returncode
        else:
            raise ValueError("Process not started yet")
