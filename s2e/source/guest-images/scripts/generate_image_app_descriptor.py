#!/usr/bin/env python3

"""
Copyright (c) 2020, Vitaly Chipounov

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
import json
import sys


def main():
    parser = argparse.ArgumentParser()

    parser.add_argument('--base-image-descriptor', '-b', dest='base_image',
                        metavar='FILE', help='Base image descriptor', type=argparse.FileType('r'))
    parser.add_argument('--app-descriptors', '-a', dest='app_descriptors',
                        metavar='FILE', help='App descriptor', type=argparse.FileType('r'))
    parser.add_argument('--app-name', '-n', dest='app_name', required=True,
                        help='App name')

    args = parser.parse_args()

    base = json.loads(args.base_image.read())
    apps = json.loads(args.app_descriptors.read())
    base['apps'] = {
        args.app_name: {
            'name': apps['apps'][args.app_name]['name'],
            'file_types': apps['apps'][args.app_name]['file_types']
        }
    }

    print(json.dumps(base, indent=4, sort_keys=True))


if __name__ == '__main__':
    main()
