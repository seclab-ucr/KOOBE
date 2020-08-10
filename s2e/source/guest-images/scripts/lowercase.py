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
import sys

def rename(root, fname):
    fpath_orig = os.path.join(root, fname)
    fpath_lower = os.path.join(root, fname.lower())
    if fpath_orig == fpath_lower:
        return

    try:
        os.rename(fpath_orig, fpath_lower)
    except Exception as e:
        print('Could not rename %s: %s' % (fpath_orig, e))

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('path', type=str, nargs=1, help='Path to folder')

    args = parser.parse_args()
    path = args.path[0]

    if not os.path.isdir(path):
        print('Path %s is not a directory' % output)
        sys.exit(-1)

    for root, dirs, files in os.walk(path, topdown=False):
        # Delete all non-executable files in this dir
        for fname in files:
            rename(root, fname)

        for d in dirs:
            rename(root, d)

if __name__ == '__main__':
    main()
