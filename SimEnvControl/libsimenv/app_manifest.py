import pathlib
import string
from typing import List, Dict, Optional, Any, Union
from SyscallAnalysis.libsyscall.target_path_converter import TargetPathConverter
from .utils import *
from SyscallAnalysis.libsyscall.analyzer.file_usage import FileUsageInfo
from SyscallAnalysis.libsyscall.syscalls.syscall import path as TargetPath


class ContentManager:
    def __init__(self, pristine_sysroot, post_sim_sysroot):
        self.post_sim_sysroot = post_sim_sysroot
        self.pristine_sysroot = pristine_sysroot
        self.pristine_path_convertor = TargetPathConverter({
            "/": pristine_sysroot
        })
        self.post_sim_path_convertor = TargetPathConverter({
            "/": post_sim_sysroot
        })

    def locate_pristine_file(self, target_path):
        # type: (str) -> Optional[str]
        expected_location = pathlib.PosixPath(
            self.pristine_path_convertor.t2h(target_path)
        )
        if expected_location.exists():
            return str(expected_location)
        else:
            return None

    def locate_post_sim_file(self, target_path):
        # type: (str) -> Optional[str]
        # remap from "/..." to "$post_sim_sysroot/..."
        expected_location = pathlib.PosixPath(
            self.post_sim_path_convertor.t2h(target_path)
        )
        if expected_location.exists():
            return str(expected_location)
        else:
            return None

    @staticmethod
    def do_sha256(res_path):
        if res_path:
            if os.path.isfile(res_path):
                return sha256(res_path)
            elif os.path.isdir(res_path):
                return "DIR"
            elif os.path.exists(res_path):
                return "SKIP"  # Skip this type of path, usually it is a device file
            else:
                return None
        else:
            return None

    def get_pristine_hash(self, target_path):
        res_path = self.locate_pristine_file(target_path)

        return self.do_sha256(res_path)

    def get_post_sim_hash(self, target_path):
        res_path = self.locate_post_sim_file(target_path)

        return self.do_sha256(res_path)


def build_manifest(app_name, app_cmd, app_init_cwd, memsize, sysroot_name,
                   pristine_sysroot, post_sim_sysroot,
                   file_usage_info, additional_inputs, copy_spawn):
    # type: (str, str, str, int, str, str, str, Dict[str, FileUsageInfo], List[str], bool) -> Dict
    manifest = dict()
    manifest["app_name"] = app_name
    manifest["app_cmd"] = app_cmd
    manifest["app_init_cwd"] = app_init_cwd
    manifest["app_memsize"] = memsize
    manifest["app_pristine_sysroot"] = sysroot_name
    if copy_spawn:
        manifest["spawn_mode"] = "copy"
    else:
        manifest["spawn_mode"] = "link"
    fs_access_dict = dict()
    manifest["fs_access"] = fs_access_dict
    content_manager = ContentManager(os.path.abspath(pristine_sysroot), os.path.abspath(post_sim_sysroot))

    def manifest_add_fs_access_entry(_path, _file_usage):
        # type: (str, FileUsageInfo) -> None

        pre_run_hash = content_manager.get_pristine_hash(_path)
        post_run_hash = content_manager.get_post_sim_hash(_path)

        if not pre_run_hash and not _file_usage.has_create():
            raise ValueError(
                "The strace shows the app used file/dir [%s] without creation, but it is not in the pristine sysroot." %
                _path
            )
        elif not post_run_hash and not _file_usage.has_remove():
            raise ValueError(
                "The strace shows the app used file/dir [%s] without removal, but it is not in the post-sim sysroot." %
                _path
            )
        elif pre_run_hash and post_run_hash and pre_run_hash != post_run_hash and not _file_usage.has_write_data():
            raise ValueError(
                "The strace shows app used file/dir [%s] without modification, but its hash changed after simulation" %
                _path
            )

        fs_access_dict[_path] = {
            "usage": str(_file_usage),
            "hash": {
                "pre-run": pre_run_hash,
                "post-run": post_run_hash
            }
        }

    for path, file_usage in file_usage_info.items():
        manifest_add_fs_access_entry(path, file_usage)

    file_usage = FileUsageInfo.build_from_str("FUSE_OPEN_RD | FUSE_READ_DATA")
    for path in additional_inputs:
        stdin_file_target_path = TargetPath(app_init_cwd, path).abspath()
        if not content_manager.locate_pristine_file(stdin_file_target_path):
            fatal(
                "Cmdline analysis shows the app will use file [%s] via stdin redirect, "
                "but it is not found in the pristine sysroot [%s]" %
                (stdin_file_target_path, pristine_sysroot)
            )
        manifest_add_fs_access_entry(stdin_file_target_path, file_usage)
        print("Added stdin redirect source [%s] to manifest" % path)
    verify_manifest_format(manifest)

    return manifest


def verify_manifest_format(manifest):
    # type: (Dict[str, Union[str, Dict]]) -> bool
    def _ensure_exist(_key):
        if _key not in manifest:
            raise ValueError("Manifest doesn't has the required field: %s" % _key)

    def _ensure_int_type(_key):
        _ensure_exist(_key)
        try:
            int(manifest[_key])
        except ValueError:
            raise ValueError("Field [%s] in the manifest is not an integer: %s" % (_key, manifest[_key]))

    def _ensure_str_type(_key):
        _ensure_exist(_key)
        if not isinstance(manifest[_key], str):
            raise ValueError("Field [%s] in the manifest is not a string: %s" % (_key, manifest[_key]))

    def _ensure_dict_type(_key):
        _ensure_exist(_key)
        if not isinstance(manifest[_key], dict):
            raise ValueError("Field [%s] in the manifest is not a map: %s" % (_key, manifest[_key]))

    def _ensure_in_set(_key, _valid_set):
        _ensure_exist(_key)
        if manifest[_key] not in _valid_set:
            raise ValueError(
                "Field [%s] in the manifest can only be one of the following value: %s" % (_key, _valid_set))

    _ensure_str_type("app_name")
    _ensure_str_type("app_cmd")
    _ensure_str_type("app_init_cwd")
    _ensure_str_type("app_pristine_sysroot")
    _ensure_int_type("app_memsize")
    _ensure_in_set("spawn_mode", {"copy", "link"})
    _ensure_dict_type("fs_access")
    for fpath, detail in manifest["fs_access"].items():
        if not pathlib.PurePosixPath(fpath).is_absolute():
            raise ValueError("In manifest['fs_access'], the key %s is not a Posix absolute path." % fpath)
        if "usage" not in detail:
            raise ValueError("Manifest['fs_access']['%s']['usage'] doesn't exist." % fpath)
        else:
            try:
                file_usage = FileUsageInfo.build_from_str(detail["usage"])
            except Exception:
                raise ValueError("Manifest['fs_access']['%s']['usage'] is invalid." % fpath)
        if "hash" not in detail:
            raise ValueError("Manifest['fs_access']['%s']['hash'] doesn't exist." % fpath)
        elif not isinstance(detail['hash'], dict):
            raise ValueError("Manifest['fs_access']['%s']['hash'] must be a map." % fpath)
        else:
            if "pre-run" not in detail['hash']:
                raise ValueError("Manifest['fs_access']['%s']['hash']['pre-run'] doesn't exist." % fpath)
            if detail['hash']['pre-run'] is None:
                pass
            elif not isinstance(detail['hash']['pre-run'], str):
                raise ValueError("Manifest['fs_access']['%s']['hash']['pre-run'] is invalid." % fpath)
            elif detail['hash']['pre-run'] not in {"DIR", "SKIP"} and not is_valid_sha256(detail['hash']['pre-run']):
                raise ValueError("Manifest['fs_access']['%s']['hash']['pre-run'] is invalid." % fpath)

            if "post-run" not in detail['hash']:
                raise ValueError("Manifest['fs_access']['%s']['hash']['post-run'] doesn't exist." % fpath)
            elif detail['hash']['post-run'] is None:
                pass
            elif detail['hash']['post-run'] is not None and not isinstance(detail['hash']['post-run'], str):
                raise ValueError("Manifest['fs_access']['%s']['hash']['post-run'] is invalid." % fpath)
            elif detail['hash']['post-run'] not in {"DIR", "SKIP"} and not is_valid_sha256(detail['hash']['post-run']):
                raise ValueError("Manifest['fs_access']['%s']['hash']['post-run'] is invalid." % fpath)

    return True
