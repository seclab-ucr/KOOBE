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
import json
import sys


def main():
    usage = '%(prog)s [options] [var1=value1 [var2=value2 ...]]'
    parser = argparse.ArgumentParser(usage=usage)

    parser.add_argument('--input-template', '-i', dest='template',
                        metavar='FILE', help='Input template path')
    parser.add_argument('--output', '-o', dest='output', metavar='FILE',
                        help='Output file path')
    parser.add_argument('--image-name', '-n', dest='image_name', required=True,
                        help='Image name')
    parser.add_argument('vars', nargs='*', help='Additional key=value pairs')

    args = parser.parse_args()

    context = {}
    for var in args.vars:
        if '=' not in var:
            parser.error('cannot parse var %s' % var)
        k, v = var.split('=', 1)
        context[k] = v

    # Get image descriptor template
    if args.template:
        with open(args.template, 'r') as f:
            template = json.loads(f.read())
    else:
        template = json.loads(sys.stdin.read())

    images = template['images']
    if args.image_name not in list(images.keys()):
        print('%s does not exist in %s' % (args.image_name, args.template))
        sys.exit(-1)

    image = images[args.image_name]

    descriptor = {
        'name': image['name'],
        'image_group': image['image_group'],
        'version': template['version'],
        'os': image['os'],
        'memory': context['memory'],
        'qemu_extra_flags': context['qemu_extra_flags'],
        'qemu_build': context['qemu_build'],
        'snapshot': context['snapshot']
    }

    output = json.dumps(descriptor, indent=4, sort_keys=True)

    if args.output:
        with open(args.output, 'w') as f:
            f.write(output)
    else:
        sys.stdout.write(output)


if __name__ == '__main__':
    main()
