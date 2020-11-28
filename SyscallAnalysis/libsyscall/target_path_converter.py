import os
import pathlib
from typing import Dict


class TargetPathConverter:
    def __init__(self, target_to_host_mapping):
        # type: (Dict[str, str]) -> None
        target_to_host_mapping = {  # remove the possible trailing "/" (e.g. correct "/usr/" to "/usr")
            str(pathlib.PurePosixPath(k)): str(pathlib.PurePosixPath(v)) for k, v in target_to_host_mapping.items()
        }
        for k, v in target_to_host_mapping.items():
            if not pathlib.PurePosixPath(k).is_absolute():
                raise ValueError("Unsupported mapping: all target mounting point must be given in a absolute path form")
            if not pathlib.PurePosixPath(v).is_absolute():
                raise ValueError("Unsupported mapping: all host path must be given in a absolute path form")

        self.t2h_mapping = target_to_host_mapping
        self.h2t_mapping = {v: k for k, v in target_to_host_mapping.items()}
        self.target_anchors = sorted([t for t in target_to_host_mapping.keys()], key=lambda s: len(s), reverse=True)
        self.host_anchors = sorted([h for h in target_to_host_mapping.values()], key=lambda s: len(s), reverse=True)

        if len(self.t2h_mapping) != len(self.h2t_mapping):
            raise RuntimeError("Unsupported mapping: A host path cannot be mapped twice: %s" % target_to_host_mapping)

    @staticmethod
    def _convert(path, anchors, mapping):
        """
        convert path using rules given by anchors and mapping
        path - the path to convert
        anchors - a list of path that sorted by the path length
        mapping - conversion mapping indexed by the anchor in anchors
        """
        for anchor in anchors:
            try:
                rel_path = pathlib.PurePosixPath(path).relative_to(anchor)
                return str(pathlib.PurePosixPath(mapping[anchor]).joinpath(rel_path))
            except ValueError:
                pass
        return None

    def t2h(self, target_path):
        if not pathlib.PurePosixPath(target_path).is_absolute():
            raise ValueError("Only absolute path can be converted")
        return self._convert(target_path, self.target_anchors, self.t2h_mapping)

    def h2t(self, host_path):
        if not pathlib.PurePosixPath(host_path).is_absolute():
            raise ValueError("Only absolute path can be converted")
        return self._convert(host_path, self.host_anchors, self.h2t_mapping)


def main():
    path_conv = TargetPathConverter({
        "/": os.path.abspath("../../SimEnvControl/libsimenv"),
        "/app": os.path.abspath("./note")
    })

    print(path_conv.t2h("/usr/include"))
    print(path_conv.t2h("/etc/hostname"))
    print(path_conv.t2h("/"))
    print(path_conv.t2h("/."))
    print(path_conv.t2h("/app"))
    print(path_conv.t2h("/app/file"))
    print(path_conv.t2h("/app/file/"))

    print(path_conv.h2t("/usr/include"))
    print(path_conv.h2t("/etc/hostname"))
    print(path_conv.h2t(os.path.abspath("../../SimEnvControl/libsimenv")))
    print(path_conv.h2t(os.path.abspath("./app")))
    print(path_conv.h2t(os.path.abspath("./app/note")))
    print(path_conv.h2t(os.path.abspath("./note")))
    print(path_conv.h2t(os.path.abspath("./note/aa")))
    print(path_conv.h2t(os.path.abspath("/")))
    # print("==========")
    # path_conv = TargetPathConverter({
    #     "/app": os.path.abspath("./note")
    # })
    #
    # print(path_conv.t2h("/usr/include"))
    # print(path_conv.t2h("/etc/hostname"))
    # print(path_conv.t2h("/"))
    # print(path_conv.t2h("/."))
    # print(path_conv.t2h("/app"))
    # print(path_conv.t2h("/app/file"))
    #
    # print(path_conv.h2t("/usr/include"))
    # print(path_conv.h2t("/etc/hostname"))
    # print(path_conv.h2t(os.path.abspath(".")))
    # print(path_conv.h2t(os.path.abspath("./app")))
    # print(path_conv.h2t(os.path.abspath("./app/note")))
    # print(path_conv.h2t(os.path.abspath("./note")))
    # print(path_conv.h2t(os.path.abspath("./note/aa")))
    # print(path_conv.h2t(os.path.abspath("/")))


if __name__ == '__main__':
    main()
