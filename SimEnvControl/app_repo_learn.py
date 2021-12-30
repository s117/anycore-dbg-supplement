#!/usr/bin/env python3
import pathlib
import click
import os

from SimEnvControl.libsimenv.repo_path import get_manifests_dir, get_sysroots_dir
from SyscallAnalysis.libsyscall.analyzer.file_usage import stat_file_usage
from SyscallAnalysis.libsyscall.analyzer.syscall_trace_constructor import SyscallTraceConstructor

from .libsimenv.autocomplete import complete_sysroot_names, complete_app_names, complete_dir, complete_path
from .libsimenv.manifest_db import save_to_manifest_db
from .libsimenv.shcmd_utils import extract_stdin_file_from_shcmd
from .libsimenv.app_manifest import build_manifest
from .libsimenv.sysroots_db import get_pristine_sysroot_dir
from .libsimenv.utils import fatal, warning


@click.command()
@click.option("--repo-path", required=True,
              type=click.Path(exists=True, dir_okay=True, file_okay=False),
              help="The app repository path.", autocompletion=complete_path)
@click.option("-n", "--app-name", required=True, help="The app name.")
@click.option("-c", "--app-cmd-file", required=True, autocompletion=complete_path,
              type=click.File(),
              help="A single-line text file that contains the command to run this app.")
@click.option("-w", "--app-init-cwd", required=True,
              help="The CWD where you started this app. Use the target path, not host path.")
@click.option("-m", "--memsize", required=True,
              type=click.INT,
              help="The amount of RAM this app needs.")
@click.option("-s", "--strace", required=True, autocompletion=complete_path,
              type=click.File(),
              help="The FESVR syscall trace file.")
@click.option("-i", "--pristine-sysroot-name", required=True, autocompletion=complete_sysroot_names,
              type=click.STRING,
              help="The path to a pristine sysroot including all the files the app needs.")
@click.option("-o", "--post-sim-sysroot-path", required=True, autocompletion=complete_dir,
              type=click.Path(exists=True, dir_okay=True, file_okay=False),
              help="The path to the sysroot after the app has run.")
@click.option("--copy-spawn", is_flag=True,
              help="When spawning this simenv, copying all it's input instead of making symbolic link.")
def learn(repo_path, app_name, app_cmd_file, app_init_cwd, memsize, strace, pristine_sysroot_name,
          post_sim_sysroot_path,
          copy_spawn):
    """
    Analyze an app for how to create SimEnv.
    """
    manifest_db_path = get_manifests_dir(repo_path)
    sysroots_archive_path = get_sysroots_dir(repo_path)

    print("Generating manifest for app %s" % app_name)
    app_cmd = app_cmd_file.read().strip()
    sysroots_archive_path = sysroots_archive_path
    pristine_sysroot_path = get_pristine_sysroot_dir(sysroots_archive_path, pristine_sysroot_name)
    if not os.path.isdir(pristine_sysroot_path):
        fatal("Cannot find pristine sysroot at \"%s\".\n" % pristine_sysroot_path)

    stdin_files = extract_stdin_file_from_shcmd(app_cmd)
    if stdin_files is None:
        warning("Fail to parse the commandline for analyzing STDIN input file(s).")
        stdin_files = []
    elif stdin_files:
        print("Recognized following file(s) passed as the input via stdin from the app run command [%s]" % app_cmd)
        for f in stdin_files:
            print("   - %s" % f)
        print("Notice: The path(s) above will be dealt as 'target path'.")

    trace_analyzer = SyscallTraceConstructor(app_init_cwd)
    strace_str = strace.read()
    trace_analyzer.parse_strace_str(strace_str)

    file_usage_info = stat_file_usage(trace_analyzer.syscalls)
    manifest = build_manifest(app_name, app_cmd, app_init_cwd, memsize, pristine_sysroot_name,
                              pristine_sysroot_path,
                              post_sim_sysroot_path,
                              file_usage_info,
                              stdin_files,
                              copy_spawn)

    save_to_manifest_db(app_name, manifest, db_path=manifest_db_path)
    print("Done.")


if __name__ == '__main__':
    learn()
