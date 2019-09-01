import os
from os import path
from subprocess import run, DEVNULL
import argparse
import shutil
import sys
import tempfile

def clobber(p):
    p = p.rstrip(path.sep)
    for x in [p, p+'.idump', p+'.rdump']:
        try:
            if path.isdir(x): shutil.rmtree(p)
            os.remove(x)
        except FileNotFoundError:
            pass

def donothing():
    pass

def dump(src, dest):
    clobber(dest)
    run(['python3', '-m', 'tbxi', 'dump', '-o', path.abspath(dest), path.abspath(src)], check=True, stdout=DEVNULL)

def build(src, dest):
    clobber(dest)
    run(['python3', '-m', 'tbxi', 'build', '-o', path.abspath(dest), path.abspath(src)], check=True, stdout=DEVNULL)

def copy_or_dump(src, dest):
    clobber(dest)
    if path.isdir(src):
        shutil.copytree(src, dest)
    else:
        dump(src, dest)

def get_src(desc=None):
    parser = argparse.ArgumentParser(description=desc)

    parser.add_argument('src', action='store', help='ROM or dump directory')
    parser.add_argument('-o', action='store', help='Optional destination path -- "file" or "directory/"'.replace('/', path.sep))

    args = parser.parse_args()
    if args.o is None: args.o = args.src

    if not path.exists(args.src):
        print('File not found', file=sys.stderr); sys.exit(1)

    if path.realpath(args.src) == path.realpath(args.o) and path.isdir(args.src):
        # Dest and source are the same, just edit in place

        return args.o, donothing

    elif args.o.endswith(path.sep):
        # Dest is a folder that we can patch then exit

        copy_or_dump(args.src, args.o)
        return args.o, donothing

    else:
        # Dest must be built from a patched temp directory

        # Follow up by building and deleting the tempfile
        tmp = tempfile.mkdtemp()
        subtmp = path.join(tmp, 'editrom')
        def cleanup():
            build(subtmp, args.o)
            shutil.rmtree(tmp)

        copy_or_dump(args.src, subtmp)
        return subtmp, cleanup
