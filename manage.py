import json
from argparse import ArgumentParser, Namespace
from json import JSONDecodeError
from os import getcwd, linesep, makedirs, path, remove, scandir, walk
from subprocess import run, CalledProcessError
from typing import Any, Literal, Optional
from zipfile import ZipFile, ZIP_DEFLATED

gray = '\x1b[90m'
reset = '\x1b[0m'
lambda_dir = path.abspath(path.join(path.dirname(__file__), 'lambda'))
layer_dir = path.abspath(path.join(path.dirname(__file__), 'layers'))
dist_dir = path.abspath(path.join(path.dirname(__file__), 'dist'))

def print_gray(
    *values: object,
    end: Optional[str] = linesep, 
    sep: Optional[str] = ' ', 
    file: Optional[Any] = None, 
    flush: Literal[False] = False
):
    print(gray, *values, reset, end=end, sep=sep, file=file, flush=flush)

def is_node_pkg(dir: str) -> bool:
    if not path.exists((pkg_json_path := path.join(dir, 'package.json'))):
        return False
    with open(pkg_json_path, 'r', encoding='utf-8') as file:
        try:
            json.load(file)
            return True
        except JSONDecodeError:
            return False

def install_packages(
    *packages: str,
    dir: str = getcwd(), 
    base_dir: str = '', 
    dev: bool = False, 
    log: bool = True
):
    dir = path.abspath(dir)
    relpath = path.relpath(dir, base_dir) if base_dir else dir
    single = len(packages) == 1
    if log: 
        print_gray(f"Installing package{'' if single else 's'} '{"', '".join(packages)}' for project {relpath}...")
    if not is_node_pkg(dir):
        if log:
            print_gray('⚠️ Directory is not a Node.js project')
        return
    if len(packages) == 0:
        if log: 
            print_gray('⚠️ No packages set to install')
        return
    cmd = f"npm install {'-D ' if dev else ''}{' '.join(packages)}"
    try:
        run(cmd, cwd=dir, shell=True, check=True, capture_output=True, text=True)
        print_gray(f"✅ {'P' if single else 'All p'}ackage{'' if single else 's'} installed")
        return
    except CalledProcessError:
        print_gray('❌ Package installation failed')
        return

def restore_project(
    dir: str = getcwd(),
    base_dir: str = '',
    clean: bool = False,
    omit: Optional[Literal['dev', 'peer', 'optional'] | list[Literal['dev', 'peer', 'optional']]] = None,
    log: bool = True
):
    dir = path.abspath(dir)
    relpath = path.relpath(dir, base_dir) if base_dir else dir
    if log:
        print_gray(f"Restoring project {relpath}...")
    if not is_node_pkg(dir):
        if log:
            print_gray('⚠️ Directory is not a Node.js project')
        return
    cmd = f"npm {'c' if clean else ''}i"
    if isinstance(omit, str) and omit:
        cmd += f" --omit={omit}"
    elif isinstance(omit, list) and len(omit):
        cmd += f" --omit={','.join(omit)}"
    try:
        run(cmd, cwd=dir, shell=True, check=True, capture_output=True, text=True)
        if log:
            print_gray('✅ Project restored')
    except CalledProcessError:
        if log:
            print_gray('❌ Project restoration failed')

def rmzip(at: str, base_dir: str = '', log: bool = True):
    abspath = path.abspath(at)
    relpath = path.relpath(abspath, base_dir) if base_dir else abspath
    if log:
        print_gray(f"Removing .zip file at {relpath}...")
    if path.isfile(abspath):
        if path.splitext(abspath)[1] == '.zip':
            remove(abspath)
            if log:
                print_gray(f"✅ .zip file removed")
        else:
            if log:
                print_gray('⚠️ Path is not a .zip file')
    else:
        if log:
            print_gray('❔ Path does not exist.')

def zipdir(source: str, dest: str, base_dir: str = '', log: bool = True):
    source = path.abspath(source)
    relpath = path.relpath(source, base_dir) if base_dir else source
    try:
        dest = path.join(dist_dir, dest)
        makedirs(path.dirname(dest), exist_ok=True)
        rmzip(dest, base_dir=path.dirname(dist_dir), log=True)
        if log: 
            print_gray(f"Packaging directory {relpath} into .zip file...")
        with ZipFile(dest, 'w', ZIP_DEFLATED) as zipfile:
            for root, _, files in walk(source):
                for file in files:
                    full_path = path.join(root, file)
                    arcname = path.relpath(full_path, source)
                    zipfile.write(full_path, arcname)
        if log:
            reldest = path.relpath(dest, path.dirname(dist_dir))
            print_gray(f"✅ Directory successfully compressed to .zip file at {reldest}")
    except Exception:
        if log:
            print_gray('❌ Directory compresion failed')
        return

def lambda_restore(args: Namespace) -> None:
    dirs = []
    all_projects: bool = args.all
    if all_projects:
        dirs = [item for item in scandir(lambda_dir) if item.is_dir()]
    else:
        projects: list[str] = args.projects
        dirs = [item for item in scandir(lambda_dir) if item.is_dir() and item.name in projects]

    if not len(dirs):
        print_gray('⚠️ No projects selected.')
        return

    for dir in dirs:
        restore_project(dir.path, base_dir=lambda_dir, omit='dev', log=True)

def lambda_install(args: Namespace) -> None:
    dirs = []
    packages: list[str] = args.packages
    dev: bool = args.dev
    all_projects: bool = args.all
    if all_projects:
        dirs = [item for item in scandir(lambda_dir) if item.is_dir()]
    else:
        projects: list[str] = args.projects
        dirs = [item for item in scandir(lambda_dir) if item.is_dir() and item.name in projects]

    if not len(dirs):
        print_gray('⚠️ No projects selected.')
        return
    for dir in dirs:
        install_packages(*packages, dir=dir.path, base_dir=lambda_dir, dev=dev, log=True)

def lambda_package(args: Namespace) -> None:
    dirs = []
    all_projects: bool = args.all
    if all_projects:
        dirs = [item for item in scandir(lambda_dir) if item.is_dir()]
    else:
        projects: list[str] = args.projects
        dirs = [item for item in scandir(lambda_dir) if item.is_dir() and item.name in projects]

    if not len(dirs):
        print_gray('⚠️ No projects selected.')
        return

    for dir in dirs:
        restore_project(dir.path, base_dir=lambda_dir, clean=True, omit='dev', log=True)
        zipdir(dir.path, path.join(path.basename(lambda_dir), f"{dir.name}.zip"), base_dir=lambda_dir, log=True)

def layer_restore(args: Namespace) -> None:
    dirs = []
    all_projects: bool = args.all
    if all_projects:
        dirs = [item for item in scandir(layer_dir) if item.is_dir()]
    else:
        projects: list[str] = args.projects
        dirs = [item for item in scandir(layer_dir) if item.is_dir() and item.name in projects]

    if not len(dirs):
        print_gray('⚠️ No layers selected.')
        return

    for dir in dirs:
        restore_project(path.join(dir.path, 'nodejs'), base_dir=layer_dir, omit='dev', log=True)

def layer_package(args: Namespace) -> None:
    dirs = []
    all_projects: bool = args.all
    if all_projects:
        dirs = [item for item in scandir(layer_dir) if item.is_dir()]
    else:
        projects: list[str] = args.projects
        dirs = [item for item in scandir(layer_dir) if item.is_dir() and item.name in projects]

    if not len(dirs):
        print_gray('⚠️ No layers selected.')
        return
    
    for dir in dirs:
        restore_project(path.join(dir.path, 'nodejs'), base_dir=layer_dir, clean=True, omit='dev', log=True)
        zipdir(dir.path, path.join(path.basename(layer_dir), f"{dir.name}.zip"), base_dir=layer_dir, log=True)

if __name__ == '__main__':
    parser = ArgumentParser(prog='cli')
    commands = parser.add_subparsers(dest='cmd')

    lambda_cmd = commands.add_parser(name='lambda', help='Commands related to the project\'s Lambda functions')
    lambda_subcmd = lambda_cmd.add_subparsers(dest='subcmd')

    lambda_restore_cmd = lambda_subcmd.add_parser(name='restore', help='Restore a project\'s packages using npm install')
    lambda_restore_cmd.add_argument('projects', nargs='*', help='The name(s) of the lambda function(s) to restore.')
    lambda_restore_cmd.add_argument(
        '-a', '--all', 
        action='store_true', 
        help='If set, ignores the arguments passed as the project names and restores all projects.'
    )
    lambda_restore_cmd.set_defaults(fn=lambda_restore)

    lambda_install_cmd = lambda_subcmd.add_parser(name='install', help='Install one or more packages to one or more projects using npm install <package_name>')
    lambda_install_cmd.add_argument('packages', nargs='+', help='The name(s) of the package(s) to install')
    lambda_install_cmd.add_argument('-p', '--projects', nargs='*', default=[], help='The name(s) of the project(s) to install the package(s) on.')
    lambda_install_cmd.add_argument(
        '-d', '--dev', 
        action='store_true',
        help='If set, installs the package(s) to devDependencies')
    lambda_install_cmd.add_argument(
        '-a', '--all', 
        action='store_true', 
        help='If set, ignores the arguments passed as the project names and installs the package(s) on all projects.'
    )
    lambda_install_cmd.set_defaults(fn=lambda_install)

    lambda_package_cmd = lambda_subcmd.add_parser(name='package', help='Clear node_modules, install all dependencies and zip the project folder(s).')
    lambda_package_cmd.add_argument('projects', nargs='*', help='The name(s) of the lambda function(s) to package.')
    lambda_package_cmd.add_argument(
        '-a', '--all', 
        action='store_true', 
        help='If set, ignores the arguments passed as the project names and packages all projects.'
    )
    lambda_package_cmd.set_defaults(fn=lambda_package)

    layer_cmd = commands.add_parser(name='layer', help='Commands related to the project\'s Lambda layers')
    layer_subcmd = layer_cmd.add_subparsers(dest='subcmd')

    layer_restore_cmd = layer_subcmd.add_parser(name='restore', help='Restore a layer\'s packages using npm install')
    layer_restore_cmd.add_argument('layer', nargs='*', help='The name(s) of the lambda layer(s) to restore.')
    layer_restore_cmd.add_argument(
        '-a', '--all', 
        action='store_true', 
        help='If set, ignores the arguments passed as the layer names and restores all layers.'
    )
    layer_restore_cmd.set_defaults(fn=layer_restore)

    layer_package_cmd = layer_subcmd.add_parser(name='package', help='Clear node_modules, install all dependencies and zip the project folder(s).')
    layer_package_cmd.add_argument('layers', nargs='*', help='The name(s) of the lambda layer(s) to package.')
    layer_package_cmd.add_argument(
        '-a', '--all', 
        action='store_true',
        help='If set, ignores the arguments passed as the layer names and packages all layers.'
    )
    layer_package_cmd.set_defaults(fn=layer_package)

    args = parser.parse_args()
    if hasattr(args, 'fn'):
        args.fn(args)