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


def app_names(args):
    js = json.loads(args.file.read())
    out = ' '.join(js['apps'].keys())
    print(out)


def base_images(args):
    js = json.loads(args.file.read())
    out = ' '.join(js['apps'][args.app_name]['base_images'])
    print(out)


def product_key(args):
    js = json.loads(args.file.read())
    print(js['apps'][args.app_name].get('product_key', ''))


def main():
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers()
    parser_app_names = subparsers.add_parser('app_names')
    parser_app_names.add_argument('file', type=argparse.FileType('r'))
    parser_app_names.set_defaults(func=app_names)

    parser_base_images = subparsers.add_parser('base_images')
    parser_base_images.add_argument('app_name', type=str)
    parser_base_images.add_argument('file', type=argparse.FileType('r'))
    parser_base_images.set_defaults(func=base_images)

    parser_product_key = subparsers.add_parser('product_key')
    parser_product_key.add_argument('app_name', type=str)
    parser_product_key.add_argument('file', type=argparse.FileType('r'))
    parser_product_key.set_defaults(func=product_key)

    args = parser.parse_args()
    args.func(args)


if __name__ == '__main__':
    main()
