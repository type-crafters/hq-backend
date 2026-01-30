import json
import subprocess
from argparse import ArgumentParser, Namespace
from functools import wraps
from inspect import signature
from json import JSONDecodeError
from os import makedirs, path, scandir, linesep, remove, walk
from shutil import rmtree
from subprocess import CalledProcessError
from typing import Callable, Literal, Optional, Mapping
from zipfile import ZIP_DEFLATED, ZipFile

__dirname = path.dirname(__file__)

lambda_dir = path.join(__dirname, 'lambda')
layer_dir = path.join(__dirname, 'layers')
dist_dir = path.join(__dirname, 'dist')

OmitPackages = Literal['peer', 'optional', 'dev']

FormatColor = Literal[
    'black', 'red', 'green', 'yellow', 'blue', 'magenta',
    'cyan', 'white', 'bright_black', 'bright_red', 'bright_green', 
    'bright_yellow', 'bright_blue', 'bright_magenta', 'bright_cyan',
    'bright_white'
]

FormatStyle = Literal['bold', 'dim', 'underline']

class Format:
    reset: str = '\x1b[0m'

    colors: Mapping[FormatColor, str] = {
        'black': '\x1b[30m',
        'red': '\x1b[31m',
        'green': '\x1b[32m',
        'yellow': '\x1b[33m',
        'blue': '\x1b[34m',
        'magenta': '\x1b[35m',
        'cyan': '\x1b[36m',
        'white': '\x1b[37m',

        'bright_black': '\x1b[90m',
        'bright_red': '\x1b[91m',
        'bright_green': '\x1b[92m',
        'bright_yellow': '\x1b[93m',
        'bright_blue': '\x1b[94m',
        'bright_magenta': '\x1b[95m',
        'bright_cyan': '\x1b[96m',
        'bright_white': '\x1b[97m',
    }

    styles: Mapping[FormatStyle, str] = {
        'bold': '\x1b[1m',
        'dim': '\x1b[2m',
        'underline': '\x1b[4m',
    }

    @classmethod
    def f(
        cls, 
        *values: object, 
        sep: str = ' ',
        end: str = '',
        color: Optional[FormatColor] = None, 
        style: Optional[FormatStyle] = None
    ) -> str:
        pre = ''
        suf = ''
        if style:
            pre += cls.styles[style]
        if color:
            pre += cls.colors[color]
        if pre:
            suf = cls.reset
        suf += end
        return pre + sep.join([str(v) for v in values]) + suf

def AssertNode(fn: Callable):
    sig = signature(fn)
    @wraps(fn)
    def wrapper(*args, **kwargs):
        bound = sig.bind(*args, **kwargs)
        bound.apply_defaults()

        
        if 'dir' not in bound.arguments:
            raise TypeError('Missing required argument \'dir\'.')
        
        dirname = path.abspath(bound.arguments.get('dir'))
        message = f"⚠️  Directory '{path.basename(dirname)}' is not a Node.js project."

        package_json = path.join(dirname, 'package.json')

        if not path.isfile(package_json):
            print(Format.f(message, color='bright_black'))
            return
        with open(package_json, 'r', encoding='utf-8') as file:
            try:
                json.load(file)
            except JSONDecodeError:
                print(Format.f(message, color='bright_black'))
                return
        return fn(*args, **kwargs)
    return wrapper

def rmzip(at: str, root: Optional[str] = None):
    at = path.abspath(at)
    relpath = path.relpath(at, root) if root else at
    print(Format.f(f"Removing .zip file at {relpath}...", color='bright_black'))
    if path.isfile(at):
        if path.splitext(at)[1] == '.zip':
            remove(at)
            print(Format.f('✅ .zip file removed', color='white'))
        else:

            print(Format.f('⚠️  Path is not a .zip file', color='bright_black'))
    else:
        print(Format.f('❔ Path does not exist.', color='bright_black'))

@AssertNode
def rm_node_modules(dir: str, root: Optional[str] = None) -> None:
    dir = path.abspath(dir)
    relpath = path.relpath(dir, root) if root else dir
    print(Format.f(f"Removing node_modules/ for directory '{relpath}'...", color='bright_black'))

    try:
        rmtree(path.join(dir, 'node_modules'))
        print(Format.f(f"✅ node_modules/ at '{relpath}' successfully removed.", color='white')) 
        return
    except (FileNotFoundError, NotADirectoryError):
        print(Format.f(f"❔ node_modules/ at '{relpath}' does not exist.", color='bright_black'))
    except PermissionError:
        print(Format.f(f"⚠️  Missing required permissions to remove node_modules/ at '{relpath}'.", color='bright_black'))
    except OSError:
        print(Format.f(f"❌ Failed to remove node_modules/ at '{relpath}'.", color='white'))

@AssertNode
def restore(dir: str, root: Optional[str] = None, omit: Optional[OmitPackages | list[OmitPackages]] = None) -> None:
    dir = path.abspath(dir)
    relpath = path.relpath(dir, root) if root else dir
    print(Format.f(f"Restoring packages for Node.js project at '{relpath}'..."))
    try:
        cmd = 'npm i'
        if isinstance(omit, str) and omit:
            cmd += f" --omit={omit}"
        elif isinstance(omit, list) and len(omit):
            cmd += f" --omit={','.join(omit)}"
        subprocess.run(cmd, cwd=dir, shell=True, check=True, capture_output=True  
                       
                       
                       )
        print(Format.f('✅ Project restored', color='white'))
    except CalledProcessError:
        print(Format.f(f"❌ Failed to restore packages at '{relpath}'.", color='white'))

@AssertNode
def npm_run(script: str, dir: str, root: str) -> None:
    dir = path.abspath(dir)
    relpath = path.relpath(dir, root) if root else dir
    print(Format.f(f"Running script '{script}' for Node.js project at '{relpath}'...", color='bright_black'))
    with open(path.join(dir, 'package.json'), 'r', encoding='utf-8') as file:
        package_json = json.load(file)
        if not package_json.get('scripts') or not package_json.get('scripts').get(script):
            print(Format.f(f"Script '{script}' is not declared in package.json at '{relpath}'."))
    cmd = f"npm run {script}"
    try: 
        subprocess.run(cmd, cwd=dir, shell=True, check=True, capture_output=True)
        print(Format.f(f"✅ Command '{cmd}' exited successfully", color='bright_black'))
    except CalledProcessError:
        print(Format.f(f"❌ Command '{cmd}' returned a non-zero status code.", color='bright_black'))

def zipdir(source: str, dest: str, root: str = ''):
    source = path.abspath(source)
    relpath = path.relpath(source, root) if root else source
    try:
        dest = path.join(dist_dir, dest)
        makedirs(path.dirname(dest), exist_ok=True)
        print(Format.f(f"Packaging directory {relpath} into .zip file...", color='bright_black'))

        with ZipFile(dest, 'w', ZIP_DEFLATED) as zipfile:
            for root, _, files in walk(source):
                for file in files:
                    full_path = path.join(root, file)
                    arcname = path.relpath(full_path, source)
                    zipfile.write(full_path, arcname)
        reldest = path.relpath(dest, path.dirname(dist_dir))
        print(Format.f(f"✅ Directory successfully compressed to .zip file at {reldest}", color='white'))
    except Exception:
        print(Format.f('❌ Directory compresion failed', color='white'))
        return
    
def resolve_dirs(args: Namespace, root: str):
    projects: list[str] = args.projects
    all: bool = args.all
    assert len(projects) or all, 'Please provide at least one project name, or the --all flag for all projects'

    return (
        [path.abspath(item.path) for item in scandir(root) if item.is_dir()] 
        if all else 
        [path.join(root, item) for item in projects if path.isdir(path.join(root, item))]
    )
    
def restore_lambda(args: Namespace):
    for dir in resolve_dirs(args, root=lambda_dir):
        rm_node_modules(dir, root=lambda_dir)
        restore(dir, root=lambda_dir)

def package_lambda(args: Namespace):
    for dir in resolve_dirs(args, root=lambda_dir):
        rmzip(path.join(dist_dir, 'lambda', f"{path.basename(dir)}.zip"), path.dirname(dist_dir))
        rm_node_modules(dir, root=lambda_dir)
        restore(dir, root=lambda_dir, omit='dev')
        npm_run('build', dir=dir, root=lambda_dir)
        zipdir(path.join(dir, 'dist'), path.join('lambda', f"{path.basename(dir)}.zip"), dist_dir)

def restore_layer(args: Namespace):
    for dir in resolve_dirs(args, root=layer_dir):
        nodejs = path.join(dir, 'nodejs')
        rm_node_modules(nodejs, root=layer_dir)
        restore(nodejs, root=layer_dir)

def package_layer(args: Namespace):
    for dir in resolve_dirs(args, root=layer_dir):
        nodejs = path.join(dir, 'nodejs')
        rmzip(path.join(dist_dir, 'layers', f"{path.basename(dir)}.zip"), path.dirname(dist_dir))
        rm_node_modules(nodejs, root=layer_dir)
        restore(nodejs, root=layer_dir, omit='dev')
        npm_run('build', dir=nodejs, root=layer_dir)
        zipdir(path.join(dir, 'dist'), path.join('layers', f"{path.basename(dir)}.zip"), dist_dir)

def main():
    # python manage.py
    manage_py = ArgumentParser(prog='tools')
    manage_cmds = manage_py.add_subparsers(dest='commands')

    # python manage.py lambda
    lambda_cmd = manage_cmds.add_parser(name='lambda', help='Commands related to the project\'s Lambda functions.')
    lambda_subcmd = lambda_cmd.add_subparsers(dest='subcommands')
    
    # python manage.py lambda restore <...projects | --all>
    lambda_restore = lambda_subcmd.add_parser(name='restore', help='Restore a Lambda function\'s packages using npm install.')
    lambda_restore.add_argument('projects', nargs='*', help='The name(s) of the lambda function(s) to restore.')
    lambda_restore.add_argument(
        '-a', '--all', 
        action='store_true', 
        help='If set, ignores the arguments passed as the project names and restores all projects.'
    )
    lambda_restore.set_defaults(fn=restore_lambda)

    # python manage.py lambda package <...projects | --all>
    lambda_package = lambda_subcmd.add_parser(name='package', help='Clean install, compile, and package a Lambda function into a deployable .zip file.')
    lambda_package.add_argument('projects', nargs='*', help='The name(s) of the lambda function(s) to package.')
    lambda_package.add_argument(
        '-a', '--all', 
        action='store_true', 
        help='If set, ignores the arguments passed as the project names and packages all projects.'
    )
    lambda_package.set_defaults(fn=package_lambda)

    # python manage.py layer
    layer_cmd = manage_cmds.add_parser(name='layer', help='Commands related to the project\'s Lambda layers.')
    layer_subcmd = layer_cmd.add_subparsers(dest='subcommands')

    # python manage.py layer restore <...layers | --all>
    layer_restore = layer_subcmd.add_parser(name='restore', help='Restore a Lambda layer\'s packages using npm install.')
    layer_restore.add_argument('projects', nargs='*', help='The name(s) of the lambda layers(s) to restore.')
    layer_restore.add_argument(
        '-a', '--all', 
        action='store_true', 
        help='If set, ignores the arguments passed as the layer names and restores all layers.'
    )
    layer_restore.set_defaults(fn=restore_layer)

    # python manage.py layer package <...layers | --all>
    layer_package = layer_subcmd.add_parser(name='package', help='Clean install, compile, and package a Lambda layer into a deployable .zip file.')
    layer_package.add_argument('projects', nargs='*', help='The name(s) of the lambda layer(s) to package.')
    layer_package.add_argument(
        '-a', '--all', 
        action='store_true', 
        help='If set, ignores the arguments passed as the layer names and packages all layers.'
    )
    layer_package.set_defaults(fn=package_layer)

    args = manage_py.parse_args()
    if hasattr(args, 'fn'):
        args.fn(args)

if __name__ == '__main__':
    main()