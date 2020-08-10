#!/usr/bin/python

# Copyright (c) 2017 Dependable Systems Laboratory, EPFL
# Copyright (c) 2018 Cyberhaven
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

from subprocess import Popen, PIPE
import sys
import os

blacklist = ['.git', 'Documentation']

files = []
for root, directories, filenames in os.walk('.'):
    for filename in filenames:
        files.append(os.path.join(root, filename))

files.sort()

dirs = set([""])
linux_files = open('linux.files', 'w')
linux_includes = open('linux.includes', 'w')
for fname in files:
    for b in blacklist:
        if b in fname:
            break
    else:
        if not os.path.isdir(fname):
            linux_files.write(fname + '\n')

            fdir = fname
            while fdir != "":
                fdir = os.path.dirname(fdir)
                if fdir not in dirs and os.path.isdir(fdir):
                    linux_includes.write(fdir + '\n')
                    dirs.add(fdir)


linux_includes.write('\n'.join([
    '../include',
]))

linux_files.close()
linux_includes.close()

with open("linux.creator", "w") as fp:
    fp.write("[General]\n")

with open("linux.config", "w") as fp:
    pass
