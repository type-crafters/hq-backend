from argparse import ArgumentParser, Namespace
from os import getcwd, linesep, makedirs, path, remove, scandir, walk
from subprocess import run, CalledProcessError
from typing import Any, Literal, Optional
from zipfile import ZipFile, ZIP_DEFLATED

gray = '\x1b[90m'
reset = '\x1b[0m'
lambda_dir = path.abspath(path.join(path.dirname(__file__), 'lambda'))
layer_dir = path.abspath(path.join(path.dirname(__file__), 'layers'))
dist = path.abspath(path.join(path.dirname(__file__), 'dist'))

def print_gray(
    *gralues: object, 
    end: str = linesep, 
    sep: str = ' ', 
    file: Optional[Any] = None, 
    flush: bool = False
):
    print(gray, *gralues, reset, end=end, sep=sep, file=file, flush=flush)

def is_node_pkg(dir: str) -> bool:
    return path.exists(path.join(dir, 'package.json'))

def install_packages(
    *packages: str,
    dir: str = getcwd(), 
    base_dir: str = '', 
    dev: bool = False, 
    log: bool = True
):
    dir = path.abspath(dir)
    relpath = path.relpath(dir, base_dir) if base_dir else dir
    if log: 
        print_gray(f"Installing packages for project {relpath}...")
    if not is_node_pkg(dir):
        if log:
            print_gray(gray, '⚠️ Directory is not a Node.js project.', reset)
        return
    if len(packages) == 0:
        if log: 
            print_gray('⚠️ No packages set to install')
        return
    cmd = f"npm install {'-D ' if dev else ''}{' '.join(packages)}"
    try:
        run(cmd, cwd=dir, shell=True, check=True, capture_output=True, text=True)
        print_gray('✅ All packages installed')
        return
    except CalledProcessError:
        print_gray('❌ Package installation failed.')
        return

def restore_project(
    dir: str = getcwd(),
    base_dir: str = '',
    omit: Optional[Literal['dev', 'peer', 'optional'] | list[Literal['dev', 'peer', 'optional']]] = None,
    log: bool = True
):
    dir = path.abspath(dir)
    relpath = path.relpath(dir, base_dir) if base_dir else dir
    if log:
        print(f"{gray}Restoring project {relpath}...{reset}")
    if not is_node_pkg(dir):
        if log:
            print_gray('⚠️ Directory is not a Node.js project.')
        return
    cmd = 'npm install'
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
            print_gray('❌ Project restoration failed.')

def rmzip(fromdir: str, log: bool = True):
    abspath = path.abspath(path.join(dist, fromdir))
    if log:
        print_gray(f"Removing all .zip files from directory {fromdir}...")
    for root, _, files in walk(abspath):
        for file in files:
            if file.endswith('.zip'):
                filepath = path.abspath(path.join(root, file))
                relpath = path.relpath(filepath, abspath)
                print_gray(f"Removing {relpath}...")
                try: 
                    remove(filepath)
                    if log:
                        print_gray(f"✅ File {relpath} eliminated successfully.")
                except:
                    if log:
                        print_gray(f"❌ Elimination of file {relpath} failed.")
                    continue

def zipnode(source: str, dest: str, base_dir: str = '', log: bool = True):

    source = path.abspath(source)
    relpath = path.relpath(source, base_dir) if base_dir else source
    if log: 
        print_gray(f"Packaging project {relpath} into .zip file...")
    if not is_node_pkg(source):
        if log:
            print_gray('⚠️ Directory is not a Node.js project.')
        return
    makedirs(dest, exist_ok=True)
    source = path.abspath(source)
    dest = path.join(dest, path.basename(source) + '.zip')
    with ZipFile(dest, 'w', ZIP_DEFLATED) as zipfile:
        for root, _, files in walk(source):
            for file in files:
                full_path = path.join(root, file)
                arcname = path.relpath(full_path, source)
                zipfile.write(full_path, arcname)

def lambda_restore(args: Namespace) -> None:
    dirs = []
    all_projects: bool = args.all
    if all_projects:
        dirs = [item for item in scandir(lambda_dir) if item.is_dir()]
    else:
        names: list[str] = args.names
        dirs = [item for item in scandir(lambda_dir) if item.is_dir() and item.name in names]

    if not len(dirs):
        print_gray('⚠️ No directories selected.')
        return

    for dir in dirs:
        restore_project(dir.path, base_dir=lambda_dir, omit='dev', log=True)


if __name__ == '__main__':
    parser = ArgumentParser(prog='cli')
    commands = parser.add_subparsers(dest='commands')

    lambda_cmd = commands.add_parser(name='lambda', help='Commands related to the project\'s Lambda functions')
    lamdba_subcmd = lambda_cmd.add_subparsers(dest='subcommands')

    lambda_restore_cmd = lamdba_subcmd.add_parser(name='restore', help='Restore a project\'s packages using npm install')
    lambda_restore_cmd.add_argument('names', nargs='*', help='The name(s) of the lambda function(s) to restore.')
    lambda_restore_cmd.add_argument(
        '-a', '--all', 
        action='store_true', 
        help='If set, ignores the arguments passed as the project names and runs the command on all projects.'
    )
    lambda_restore_cmd.set_defaults(fn=lambda_restore)

    layer_cmd = commands.add_parser(name='layer', help='Commands related to the project\'s Lambda layers')
    layer_cmd.add_subparsers(dest='subcommands')

    args = parser.parse_args()
    if hasattr(args, 'fn'):
        args.fn(args)