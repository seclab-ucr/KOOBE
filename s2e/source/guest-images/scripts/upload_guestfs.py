#!/usr/bin/env python2

"""
Copyright (c) 2014-2020 Cyberhaven

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the 'Software'), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED 'AS IS', WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
"""

# This script must be kept in Python 2 because it is used on Windows XP guests
# to upload files to the host. Windows XP doesn't have recent Python 3 support.

# Do not use any non-standard libraries
import sys
import os
import ftplib
import hashlib


class FTPConnection:
    def __init__(self, host, port):
        self._ftp = ftplib.FTP()
        self._ftp.connect(host, port)
        self._ftp.login()
        self._existing_dirs = set()

    def upload(self, localfile, remotefile):
        dir = os.path.dirname(remotefile)

        try:
            self._ftp.cwd(dir)
        except:
            self.mkdir(dir)
            self._ftp.cwd(dir)

        print('Uploading %s to %s' % (localfile, remotefile))
        with open(localfile, 'rb') as f:
            self._ftp.storbinary('STOR ' + remotefile, f)

    def mkdir(self, dir):
        dirs = dir.split('/')
        cdir = ''

        for d in dirs:
            cdir = cdir + d + '/'
            if cdir in self._existing_dirs:
                continue

            try:
                self._ftp.mkd(cdir)
                self._existing_dirs.add(cdir)
            except ftplib.error_perm as e:
                if str(e)[:3] == '550':
                    self._existing_dirs.add(cdir)
            except:
                pass

    def close(self):
        try:
            self._ftp.quit()
        except:
            self._ftp.close()


def read_excludes(filename):
    with open(filename, 'rt') as f:
        files = {}
        for line in f.readlines():
            values = line.split(' ')
            cksum, fn = values[0], ' '.join(values[1:])
            files[fn.strip('\n').lower()] = cksum
        return files


def is_binary(filename):
    try:
        with open(filename, 'rb') as f:
            data = f.read(2)
            if len(data) != 2 or data != 'MZ':
                return False
            return True
    except Exception as e:
        print(str(e))
        return False


def hashfile(filename, hasher, blocksize=65536):
    with open(filename, 'rb') as fp:
        buf = fp.read(blocksize)
        while len(buf) > 0:
            hasher.update(buf)
            buf = fp.read(blocksize)
        return hasher.hexdigest()
    return '*'


def find_exclude_entry(filename, exclude_list):
    if filename in exclude_list:
        return exclude_list[filename]
    return None


def should_copy(filename, exclude_list):
    # Only copy executables
    if not is_binary(filename):
        return False

    # Copy if it's not on the list
    entry = find_exclude_entry(filename, exclude_list)
    if entry is None:
        return True

    # Wildcard hash for our own use
    if entry == '*':
        return False

    # Copy if hash is different
    newhash = hashfile(filename, hashlib.md5())
    if newhash != entry:
        return True

    return False


def upload_file(connection, localfile, prefix):
    if prefix[0] != '/':
        prefix = '/' + prefix

    if os.name == 'nt':
        remotefile = prefix + localfile[2:].replace('\\', '/')
    else:
        remotefile = prefix + '/' + localfile

    connection.upload(localfile, remotefile)


def find_and_upload(rootpath, exclude_list, connection, prefix):
    print('Building list of files in {}'.format(rootpath))
    for root, dirs, files in os.walk(rootpath):
        dirs.sort()
        files.sort()

        if root == '.':
            root = ''

        for f in files:
            fp = os.path.join(root, f).lower()
            if should_copy(fp, exclude_list):
                upload_file(connection, fp, prefix)


def main():
    if len(sys.argv) != 5:
        print('Usage: {} files_to_exclude.txt server:port ftpprefix root'.format(sys.argv[0]))
        sys.exit(1)

    exclude_file = sys.argv[1]
    remote = sys.argv[2]
    prefix = sys.argv[3]
    root = sys.argv[4]

    if ':' in remote:
        host, port = remote.split(':')
    else:
        host = remotehost
        port = 21

    ftp = FTPConnection(host, int(port))

    exclude_list = read_excludes(exclude_file)
    print('{} files in the exclude list'.format(len(exclude_list)))

    find_and_upload(root, exclude_list, ftp, prefix)

    ftp.close()


if __name__ == '__main__':
    main()
