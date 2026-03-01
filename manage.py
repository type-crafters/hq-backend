import json
import subprocess
from argparse import ArgumentParser, Namespace
from datetime import datetime
from functools import wraps
from glob import glob
from os import makedirs, path, scandir, remove, walk
from subprocess import CalledProcessError
from typing import Callable, Optional, Literal
from zipfile import ZipFile, ZIP_DEFLATED


ROOT_DIR = path.abspath('.')
DIST_DIR = path.join(ROOT_DIR, 'dist')


"""
--------------------------------------------------
Utilities
--------------------------------------------------
"""

def abortable(fn: Callable):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        try:
            return fn(*args, **kwargs)
        except KeyboardInterrupt:
            print("Operation aborted.")
            exit(1)
    return wrapper


def assert_node_project(directory: str) -> bool:
    package_json = path.join(directory, 'package.json')
    if not path.isfile(package_json):
        print(f"Skipping '{path.basename(directory)}' (not a Node project)")
        return False

    try:
        with open(package_json, 'r', encoding='utf-8') as f:
            json.load(f)
    except json.JSONDecodeError:
        print(f"Invalid package.json in '{directory}'")
        return False

    return True


def run_cmd(cmd: list[str], cwd: str, capture: bool = True):
    return subprocess.run(
        ' '.join(cmd),
        cwd=cwd,
        shell=True,
        check=True,
        capture_output=capture,
        text=True
    )


"""
--------------------------------------------------
Core Operations
--------------------------------------------------
"""

def restore(directory: str, clean: bool = False, omit: Optional[Literal['dev']] = None):
    if not assert_node_project(directory):
        return

    cmd = ['npm', 'ci'] if clean else ['npm', 'install']

    if omit:
        cmd.append(f'--omit={omit}')

    print(f"Restoring packages in '{path.basename(directory)}'...")
    try:
        run_cmd(cmd, cwd=directory)
        print("✅ Packages restored")
    except CalledProcessError:
        print("❌ Failed to restore packages")


def npm_run(script: str, directory: str, show_output: bool = False):
    if not assert_node_project(directory):
        return

    package_json_path = path.join(directory, 'package.json')
    with open(package_json_path, 'r', encoding='utf-8') as f:
        package = json.load(f)

    if script not in package.get('scripts', {}):
        print(f"Script '{script}' not found in {path.basename(directory)}")
        return

    print(f"Running '{script}' in '{path.basename(directory)}'...")

    try:
        run_cmd(['npm', 'run', script], cwd=directory, capture=not show_output)
        print("✅ Script succeeded")
    except CalledProcessError as e:
        log_path = path.join(directory, 'build-process.log')
        with open(log_path, 'a+', encoding='utf-8') as log:
            log.write(
                f"[{datetime.now()}] Script '{script}' failed\n"
                f"stdout:\n{e.stdout}\n\nstderr:\n{e.stderr}\n\n"
            )

        print(f"❌ Script failed. See {log_path}")


def zip_directory(source: str, output_name: str, ignore: list[str] = []):
    dest = path.join(DIST_DIR, output_name)
    makedirs(path.dirname(dest), exist_ok=True)

    ignore_files = {
        path.abspath(p)
        for pattern in ignore
        for p in glob(path.join(source, pattern), recursive=True)
    }

    print(f"Packaging '{path.basename(source)}'...")

    try:
        with ZipFile(dest, 'w', ZIP_DEFLATED) as zipf:
            for root, _, files in walk(source):
                for file in files:
                    full_path = path.join(root, file)
                    if full_path in ignore_files:
                        continue
                    arcname = path.relpath(full_path, source)
                    zipf.write(full_path, arcname)

        print(f"✅ Created {dest}")
    except Exception:
        print("❌ Failed to create zip")


"""
--------------------------------------------------
Lambda Packaging
--------------------------------------------------
"""

@abortable
def install_lambda(args: Namespace):
    for directory in resolve_projects(args):
        if not assert_node_project(directory):
            continue

        name = path.basename(directory)
        print(f"Installing packages in '{name}'...")

        try:
            run_cmd('npm install', cwd=directory)
            print("✅ Packages installed\n")
        except CalledProcessError:
            print(f"❌ Failed to install in '{name}'\n")

@abortable
def restore_lambda(args: Namespace):
    for directory in resolve_projects(args):
        restore(directory, clean=True)


@abortable
def package_lambda(args: Namespace):
    for directory in resolve_projects(args):
        name = path.basename(directory)
        zip_name = f"{name}.zip"

        restore(directory)
        npm_run('test', directory, show_output=True)
        npm_run('build', directory)
        restore(directory, clean=True, omit='dev')

        zip_directory(
            source=directory,
            output_name=zip_name,
            ignore=[
                'src/**/*',
                'package-lock.json',
                '*.log',
                '**/test/**/*'
            ]
        )


"""
--------------------------------------------------
Project Resolution
--------------------------------------------------
"""

def resolve_projects(args: Namespace):
    if not args.all and not args.projects:
        raise ValueError("Provide project names or use --all")

    if args.all:
        return [
            entry.path
            for entry in scandir(ROOT_DIR)
            if entry.is_dir()
        ]

    return [
        path.join(ROOT_DIR, name)
        for name in args.projects
        if path.isdir(path.join(ROOT_DIR, name))
    ]

"""
--------------------------------------------------
CLI
--------------------------------------------------
"""

def main():
    parser = ArgumentParser(prog='lambda-tools')
    subparsers = parser.add_subparsers(dest='command')

    # restore
    restore_cmd = subparsers.add_parser('restore')
    restore_cmd.add_argument('projects', nargs='*')
    restore_cmd.add_argument('-a', '--all', action='store_true')
    restore_cmd.set_defaults(fn=restore_lambda)

    # package
    package_cmd = subparsers.add_parser('package')
    package_cmd.add_argument('projects', nargs='*')
    package_cmd.add_argument('-a', '--all', action='store_true')
    package_cmd.set_defaults(fn=package_lambda)

    # install
    install_cmd = subparsers.add_parser(
        'install',
        help='Install dependencies in one or more Lambda projects.'
    )
    install_cmd.add_argument(
        'projects',
        nargs='*',
        help='Lambda project directories to install.'
    )
    install_cmd.add_argument(
        '-a',
        '--all',
        action='store_true',
        help='Install in all Lambda directories.'
    )
    install_cmd.set_defaults(fn=install_lambda)

    args = parser.parse_args()

    if hasattr(args, 'fn'):
        args.fn(args)
    else:
        parser.print_help()

if __name__ == '__main__':
    main()