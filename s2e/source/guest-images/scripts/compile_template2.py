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
import jinja2
import json
import sys


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-t', '--template', help='Template file', required=True, type=argparse.FileType('r'))
    parser.add_argument('vars', nargs='*', help='key=value pairs')

    args = parser.parse_args()

    context = {}
    for var in args.vars:
        if '=' not in var:
            parser.error('cannot parse var %s' % var)
        k, v = var.split('=', 1)
        context[k] = v

    template = jinja2.Template(args.template.read())

    print(template.render(**context))


if __name__ == '__main__':
    main()
