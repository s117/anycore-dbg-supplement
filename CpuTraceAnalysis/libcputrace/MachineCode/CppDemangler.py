import subprocess


class CppDemangler:
    cpp_filt_available = False
    demangled_cache = dict()

    @classmethod
    def check_cpp_filt_avail(cls):
        try:
            args = ['c++filt', '--version']
            pipe = subprocess.Popen(args, stdin=subprocess.PIPE, stdout=subprocess.PIPE)
            stdout, _ = pipe.communicate()
            ret_code = pipe.wait()
            if ret_code == 0:
                cls.cpp_filt_available = True
        finally:
            pass

    @classmethod
    def demangle(cls, name):
        if not cls.cpp_filt_available:
            return name
        if name not in cls.demangled_cache:
            cls.demangled_cache[name] = cls._do_demangle(name)
        return cls.demangled_cache[name]

    @staticmethod
    def _do_demangle(name):
        args = ['c++filt', name]
        pipe = subprocess.Popen(args, stdin=subprocess.PIPE, stdout=subprocess.PIPE)
        stdout, _ = pipe.communicate()
        demangled = stdout.decode("utf-8").split('\n')

        # Each line ends with a newline, so the final entry of the split output
        # will always be ''.
        assert len(demangled) == 2
        return demangled[0]

    @staticmethod
    def _do_demangle_list(names):
        args = ['c++filt']
        args.extend(names)
        pipe = subprocess.Popen(args, stdin=subprocess.PIPE, stdout=subprocess.PIPE)
        stdout, _ = pipe.communicate()
        demangled = stdout.decode("utf-8").split('\n')

        # Each line ends with a newline, so the final entry of the split output
        # will always be ''.
        assert len(demangled) == len(names) + 1
        return demangled[:-1]


CppDemangler.check_cpp_filt_avail()
