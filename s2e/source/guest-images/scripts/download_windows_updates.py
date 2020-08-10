#!/usr/bin/env python3

"""
Copyright (c) 2020, Cyberhaven

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
import os
import sys
import urllib.request

import xml.etree.ElementTree as ET

g_ignored_categories = [25]


def eprint(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)


def get_file_name(update):
    category = int(update.attrib['category'])
    publish_date = update.attrib['publishdate']
    filename = update.find('filename').text
    return f'%02d_{publish_date}_{filename}' % category


def gen_makefile_target(output_dir, update):
    file_path = os.path.join(output_dir, get_file_name(update))
    url = update.find('url').text.strip()
    title = update.find('title').text.strip()
    print(f'# {title}')
    print(f'{file_path}: | {output_dir}')
    print(f'\t$(WGET) $@ {url}')
    print('')


def get_update_list(root):
    update_list = []
    for child in root:
        if child.tag == 'updates':
            for update in child:
                update_list.append((get_file_name(update), update))

    return sorted(update_list, key=lambda x:x[1].attrib['id'])
    # return update_list


def handle_makefile(args, root):
    print('# Automatically generated')
    cmdline = ' '.join(sys.argv)
    print(f'# {cmdline}\n')

    print(f'{args.output_prefix}:')
    print(f'\tmkdir -p $@')

    targets = []
    ul = get_update_list(root)
    for file_path, update in ul:
        category = int(update.attrib['category'])
        if category not in g_ignored_categories:
            gen_makefile_target(args.output_prefix, update)
            targets.append(os.path.join(args.output_prefix, file_path))

    file_paths = ' '.join(targets)
    print(f'{args.var_name} := $({args.var_name}) {file_paths}')


def handle_download(args, root):
    if not os.path.isdir(args.output_dir):
        eprint('%s is not a directory' % args.output_dir)
        sys.exit(-1)

    for child in root:
        print(child.tag, child.attrib)
        if child.tag == 'updates':
            for update in child:
                category = int(update.attrib['category'])
                if category in g_ignored_categories:
                    print(f'Ignoring category 25 (windows 10 and telemetry updates)')
                    continue

                publish_date = update.attrib['publishdate']
                title = update.find('title').text
                filename = update.find('filename').text
                url = update.find('url').text
                print(publish_date, title, filename, url)

                file_name = get_file_name(update)
                file_path = os.path.join(args.output_dir, file_name)

                if os.path.exists(file_path):
                    print(f'{file_path} exists, skipping')
                else:
                    print(f'Downloading {url} to {file_path}')
                    urllib.request.urlretrieve(url, file_path)


def main():
    parser = argparse.ArgumentParser()

    subparser = parser.add_subparsers()
    makefile = subparser.add_parser('makefile')
    makefile.add_argument('-o', '--output-prefix', help='Output prefix', required=True)
    makefile.add_argument('-f', '--update-file', help='Path to the XML file that describes the updates', required=True)
    makefile.add_argument('-v', '--var-name', help='Variable that contains all the targets', required=True)
    makefile.set_defaults(func=handle_makefile)

    download = subparser.add_parser('download')
    download.add_argument('-o', '--output-dir', help='Output directory', required=True)
    download.add_argument('-f', '--update-file', help='Path to the XML file that describes the updates', required=True)
    download.set_defaults(func=handle_download)

    args = parser.parse_args()

    if not os.path.isfile(args.update_file):
        eprint('%s does not exist' % args.update_file)
        sys.exit(-1)

    root = ET.parse(args.update_file).getroot()

    args.func(args, root)


if __name__ == '__main__':
    main()
