#!/usr/bin/env python3

"""
Copyright (c) 2017, Cyberhaven

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
"""


import argparse
import os
import re
import shutil
import sys


def is_executable(filename):
    with open(filename, 'rb') as fp:
        header = fp.read(4)
        if header == b'.ELF':
            return True
        elif header[0:2] == b'MZ':
            return True
    return False


def copy_executables():
    parser = argparse.ArgumentParser()
    parser.add_argument('source', type=str, nargs=1, help='Path to source folder')
    parser.add_argument('dest', type=str, nargs=1, help='Path to dest folder')

    args = parser.parse_args()
    source = args.source[0]
    dest = args.dest[0]

    if not os.path.isdir(source):
        print('Path %s is not a directory' % source)
        sys.exit(-1)

    if not os.path.isdir(dest):
        print('Path %s is not a directory' % dest)
        sys.exit(-1)

    for root, dirs, files in os.walk(source, topdown=False):
        for fname in files:
            fpath = os.path.join(root, fname)
            if not os.path.isfile(fpath):
                continue

            if not is_executable(fpath):
                continue

            source_dir_suffix = root[len(source)+1:]
            dest_dir = os.path.join(dest, source_dir_suffix)

            if not os.path.exists(dest_dir):
                os.makedirs(dest_dir)

            shutil.copy(fpath, dest_dir)


if __name__ == '__main__':
    copy_executables()
