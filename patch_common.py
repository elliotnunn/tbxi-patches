from os import path
from subprocess import run, DEVNULL
import argparse
import shutil
import sys
import tempfile

def get_src(desc=None):
    parser = argparse.ArgumentParser(description=desc)

    parser.add_argument('src', action='store', help='Original (ROM or dumped dir)')
    parser.add_argument('-o', action='store', help='New')

    args = parser.parse_args()

    if not path.exists(args.src):
        print('File not found', file=sys.stderr); sys.exit(1)

    if not path.isdir(args.src) and args.o is None:
        print('Cannot edit a ROM in place, use -o', file=sys.stderr); sys.exit(1)

    if path.isdir(args.src):
        def cleanup():
            pass

        if args.o:
            try:
                shutil.rmtree(args.o)
            except FileNotFoundError:
                pass
            shutil.copytree(args.src, args.o)
            src = args.o
        else:
            src = args.src

    else:
        tmp = tempfile.mkdtemp()
        src = path.join(tmp, 'editrom')

        run(['python3', '-m', 'tbxi', 'dump', '-o', src, args.src], check=True, stdout=DEVNULL)

        def cleanup():
            run(['python3', '-m', 'tbxi', 'build', '-o', args.o, src], check=True, stdout=DEVNULL)
            shutil.rmtree(tmp)

    return src, cleanup
