import json
import subprocess
from argparse import ArgumentParser, Namespace
from datetime import datetime
from functools import wraps
from glob import glob
from inspect import signature
from json import JSONDecodeError
from os import makedirs, path, scandir, remove, walk
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

def Abortable(fn: Callable): 
    @wraps(fn)
    def wrapper(*args, **kwargs):
        try:
            return fn(*args, **kwargs)
        except KeyboardInterrupt:
            print(Format.f("User aborted operation (Ctrl + C)", color='red'))
            exit(1)
    return wrapper

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
    print(Format.f(f"Removing .zip file at '{relpath}'...", color='bright_black'))
    if path.isfile(at):
        if path.splitext(at)[1] == '.zip':
            remove(at)
            print(Format.f('✅ .zip file removed', color='white'))
        else:

            print(Format.f('⚠️  Path is not a .zip file', color='bright_black'))
    else:
        print(Format.f('❔ Path does not exist.', color='bright_black'))

@AssertNode
def restore(
    dir: str, 
    root: Optional[str] = None, 
    omit: Optional[OmitPackages | list[OmitPackages]] = None,
    clean: bool = False
    ) -> None:
    dir = path.abspath(dir)
    relpath = path.relpath(dir, root) if root else dir

    message = f"{'Clean-r' if clean else 'R'}estoring packages for Node.js project at '{relpath}'"
    cmd = 'npm ci' if clean else 'npm i'

    if omit is not None:
        message += "; Omitting '"
        if isinstance(omit, str) and omit:
            message += f"{omit}'"
            cmd += f" --omit={omit}"
        elif isinstance(omit, list) and len(omit):
            message += f"{"', '".join(omit)}'"
            cmd += f" --omit={','.join(omit)}"
        message += " packages"
    message += "..."

    print(Format.f(message, color='bright_black'))


    try:
        subprocess.run(cmd, cwd=dir, shell=True, check=True, capture_output=True)
        print(Format.f('✅ Project restored', color='white'))
    except CalledProcessError:
        print(Format.f(f"❌ Failed to restore packages at '{relpath}'.", color='white'))

@AssertNode
def npm_run(script: str, dir: str, root: str) -> None:
    dir = path.abspath(dir)
    relpath = path.relpath(dir, root) if root else dir
    pkg_script = ''
    print(Format.f(f"Running script '{script}' for Node.js project at '{relpath}'...", color='bright_black'))
    with open(path.join(dir, 'package.json'), 'r', encoding='utf-8') as file:
        package_json = json.load(file)
        if not package_json.get('scripts') or not (pkg_script := package_json.get('scripts').get(script)):
            print(Format.f(f"Script '{script}' is not declared in package.json at '{relpath}'.", color='bright_black'))
            return
    cmd = f"npm run {script}"
    try: 
        subprocess.run(cmd, cwd=dir, shell=True, check=True, capture_output=True, text=True)
        print(
            Format.f("✅ Command", color='white'),
            Format.f(f"'{cmd}'", color='blue'),
            Format.f(f"exited successfully.", color='white')
        )
    except CalledProcessError as e:
        log = [
            f"[{datetime.now().strftime("%Y-%m-%d %H:%M:%S")}]",
            f"({path.basename(dir)})",
            f"script '{script}': {pkg_script}",
            'stdout:',
            e.stdout,
            'stderr:',
            e.stderr,
            ''
        ]

        with open(path.join(dir, 'build-process.log'), 'a+', encoding='utf-8') as file:
            file.write('\n'.join(log))

        print(
            Format.f("❌ Command", color='white'),
            Format.f(f"'{cmd}'", color='red'),
            Format.f(f"returned a non-zero status code. Check", color='white'),
            Format.f(path.join(dir, 'build-process.log'), color='cyan'),
            Format.f("for more information.", color='white')
        )

def zipdir(source: str, dest: str, root: str = '', ignore: list[str] = []):
    source = path.abspath(source)
    dest = path.join(dist_dir, dest)
    relsrc = path.relpath(source, root) if root else source
    reldest = path.relpath(dest, path.dirname(dist_dir))

    ignorelist = []
    if len(ignore):
        ignorelist = [path.abspath(p) for pattern in ignore for p in glob(path.join(source, pattern), recursive=True)]

    ignorable = bool(len(ignorelist))

    try:
        makedirs(path.dirname(dest), exist_ok=True)
        print(Format.f(f"Packaging directory '{relsrc}' into .zip file...", color='bright_black'))
        with ZipFile(dest, 'w', ZIP_DEFLATED) as zipfile:
            for dirpath, _, files in walk(source):
                for file in files:
                    fullpath = path.join(dirpath, file)
                    if ignorable and fullpath in ignorelist:
                        continue
                    arcname = path.relpath(fullpath, source)
                    zipfile.write(fullpath, arcname)
        print(Format.f(f"✅ Directory successfully compressed to .zip file at '{reldest}'", color='white'))
    except Exception:
        print(Format.f('❌ Directory compresion failed', color='white'))
        return

@AssertNode
def pack_layer(dir: str, root: str = ''):
    dir = path.abspath(dir)
    relpath = path.relpath(dir, root) if root else dir

    print(Format.f(f"Packing project at {relpath} into a tarball...", color='bright_black'))
    try: 
        result = subprocess.run('npm pack --json', cwd=dir, shell=True, check=True, capture_output=True)
        try: 
            tarball = json.loads(result.stdout)[0]['filename']
        except KeyError:
            print(Format.f('❌ Could not read filename for tarball.'))
            return
        print(Format.f('✅ Tarball creation succeeded.', color='white'))
    except CalledProcessError:
        print(Format.f('❌ Failed to create tarball.', color='white'))
        return
    
    print(Format.f('Creating layer structure...', color='bright_black'))
    cmd = ['npm', 'install', tarball, '--prefix', 'nodejs']
    try:
        subprocess.run(
            ' '.join(cmd), 
            cwd=dir, 
            shell=True, 
            check=True, 
            capture_output=True,
        )
        
        print(Format.f(f"✅ Layer folder created at {path.join(relpath, 'nodejs')}.", color='white'))
    except CalledProcessError:
        print(Format.f('❌ Failed to create layer structure.', color='white'))

    print(Format.f('All in order. Removing tarball...', color='bright_black'))
    try:
        remove(path.join(dir, tarball))
        print(Format.f('✅ Tarball removed.', color='white'))
    except OSError:
        print(Format.f(f"❌ Failed to remove {tarball}", color='white'))

def resolve_dirs(args: Namespace, root: str):
    projects: list[str] = args.projects
    all: bool = args.all
    assert len(projects) or all, 'Please provide at least one project name, or the --all flag for all projects'

    return (
        [path.abspath(item.path) for item in scandir(root) if item.is_dir()] 
        if all else 
        [path.join(root, item) for item in projects if path.isdir(path.join(root, item))]
    )


@Abortable
def restore_lambda(args: Namespace):
    for dir in resolve_dirs(args, root=lambda_dir):
        restore(dir, root=lambda_dir, clean=True)
        print()

@Abortable
def package_lambda(args: Namespace):
    for dir in resolve_dirs(args, root=lambda_dir):
        zipname = f"{path.basename(dir)}.zip"
        rmzip(at=path.join(dist_dir, 'lambda', zipname), root=__dirname)
        restore(dir, root=lambda_dir)
        npm_run('build', dir=dir, root=lambda_dir)
        restore(dir, root=lambda_dir, omit='dev', clean=True)
        zipdir(
            source=dir,
            dest=path.join('lambda', zipname),
            root=__dirname,
            ignore=['src/**/*', 'package-lock.json', '*.log']
        )
        print()

@Abortable
def restore_layer(args: Namespace):
    for dir in resolve_dirs(args, root=layer_dir):
        restore(dir, root=layer_dir, clean=True)
        print()

@Abortable
def package_layer(args: Namespace):
    for dir in resolve_dirs(args, root=layer_dir):
        zipname = f"{path.basename(dir)}.zip"

        rmzip(at=path.join(dist_dir, 'layers', zipname), root=__dirname)
        restore(dir=dir, root=layer_dir)
        npm_run('build', dir=dir, root=layer_dir)
        pack_layer(dir=dir, root=layer_dir)
        zipdir(
            source=path.join(dir, 'nodejs'), 
            dest=path.join('layers', zipname), 
            root=__dirname,
            ignore=['src/**/*', 'package-lock.json']
        )
        print()


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
