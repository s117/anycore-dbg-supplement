#!/usr/bin/env python3
import shutil
import stat

import click

from SimEnvControl.libsimenv.sysroots_db import get_pristine_sysroot_dir
from .libsimenv.autocomplete import complete_app_names, complete_dir
from .libsimenv.app_manifest import *
from .libsimenv.manifest_db import *

from .libsimenv.utils import *


@click.command()
@click.pass_context
@click.argument("app-name", autocompletion=complete_app_names, type=click.STRING)
@click.argument("dest-dir", autocompletion=complete_dir, type=click.Path())
@click.option("-f", "--force", is_flag=True,
              help="If path [new-dir] already exist, remove it before create the new simenv.")
@click.option("-c", "--copy-mode", is_flag=True,
              help="Copy the file to the new simenv, regardless the spawn mode given by the manifest.")
def spawn(ctx, app_name, dest_dir, force, copy_mode):
    """
    Spawn a simenv.
    """
    manifest_db_path = ctx.obj['manifest_db_path']
    sysroots_archive_path = ctx.obj['sysroots_archive_path']

    if os.path.exists(dest_dir):
        if force:
            succ, msg = remove_path(dest_dir)
            if not succ:
                fatal("Fail to remove \"%s\", reason:\n%s" % (dest_dir, msg))
        else:
            fatal("Path \"%s\" already exist, new simenv not spawned." % dest_dir)
    print("Spawning simenv for app %s" % app_name)
    os.makedirs(dest_dir, exist_ok=True)

    try:
        manifest = load_from_manifest_db(app_name, manifest_db_path)
        verify_manifest_format(manifest)
    except FileNotFoundError:
        print("Fatal: No manifest file for app '%s'" % app_name, file=sys.stderr)
        prompt_app_name_suggestion(app_name, manifest_db_path)
        sys.exit(-1)
    except ValueError as ve:
        fatal("%s has a malformed manifest (%s)" % (app_name, ve))
    else:
        app_name = manifest["app_name"]
        app_cmd = manifest["app_cmd"]
        app_init_cwd = manifest["app_init_cwd"]
        app_pristine_sysroot_name = manifest["app_pristine_sysroot"]
        app_pristine_sysroot_path = get_pristine_sysroot_dir(sysroots_archive_path, app_pristine_sysroot_name)
        app_memsize = manifest["app_memsize"]
        link_mode = not copy_mode and manifest["spawn_mode"] == "link"

        if not os.path.isdir(app_pristine_sysroot_path):
            fatal("App's pristine sysroot [%s] does not exist" % app_pristine_sysroot_path)

        pristine_path_converter = TargetPathConverter({"/": os.path.abspath(app_pristine_sysroot_path)})
        spawn_path_converter = TargetPathConverter({"/": os.path.abspath(dest_dir)})

        def spawn_file(src, dst):
            assert dst
            assert src
            par_dir = os.path.dirname(dst)
            spawn_dir(par_dir)
            if os.path.isdir(dst):
                fatal("Malformed manifest input: %s implies both input file and dir" % dst)
            if link_mode:
                os.symlink(src, dst)
                print("Symlink %s -> %s" % (src, dst))
            else:
                shutil.copy2(src, dst, follow_symlinks=False)
                print("Copy %s -> %s" % (src, dst))

        def spawn_dir(dpath):
            if dpath:
                if os.path.isfile(dpath):
                    fatal("Malformed manifest input: %s implies both dir and input" % dpath)
                os.makedirs(dpath, exist_ok=True)
                print("Mkdir %s" % dpath)

        for pname, details in manifest['fs_access'].items():
            pre_run_hash = details['hash']['pre-run']
            file_usage = FileUsageInfo.build_from_str(details['usage'])
            if pre_run_hash:
                if pre_run_hash == 'DIR':
                    spawn_dir(spawn_path_converter.t2h(pname))
                else:
                    file_src = pristine_path_converter.t2h(pname)
                    file_dst = spawn_path_converter.t2h(pname)
                    spawn_file(
                        file_src,
                        file_dst
                    )
                    if not link_mode and (
                            file_usage.has_remove() or
                            file_usage.has_create() or
                            file_usage.has_open_wr() or
                            file_usage.has_open_rw() or
                            file_usage.has_write_data()
                    ):
                        # in copy mode, automatic set the write permission if needed by the app
                        if not os.access(file_dst, os.W_OK):
                            st = os.stat(file_dst)
                            os.chmod(file_dst, st.st_mode | stat.S_IWRITE)


if __name__ == '__main__':
    spawn()
