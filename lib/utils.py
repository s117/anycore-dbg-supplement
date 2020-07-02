from typing import Optional


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
