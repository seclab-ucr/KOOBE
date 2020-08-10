#!/bin/sh

# Copyright (c) 2017, Cyberhaven
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


set -e

echo $*

if [ $# -ne 2 ]; then
    echo "Usage: $0 http://url/to/image output_file"
    echo
    echo "The image can be a normal iso file or a jigdo file."
    exit 1
fi

IMAGE_URL="$1"
OUTPUT_FILE="$2"
EXTENSION="${IMAGE_URL##*.}"

download()
{
    local IMAGE_URL
    local OUTPUT_FILE

    IMAGE_URL="$1"
    OUTPUT_FILE="$2"

    echo "Downloading $IMAGE_URL to $OUTPUT_FILE"
    wget --no-use-server-timestamps -O "$OUTPUT_FILE" "$IMAGE_URL"
}

# Note: this assumes that the jigdo and the associated template file are in the same
# directory on the server.
download_jigdo()
{
    local IMAGE_URL
    local OUTPUT_FILE
    local TEMPLATE_URL
    local ISO_FILE
    local JIGDO_FILE

    IMAGE_URL="$1"
    OUTPUT_FILE="$2"
    TEMPLATE_URL="${IMAGE_URL%.*}.template"
    ISO_FILE="$(basename "${IMAGE_URL%.*}.iso")"
    JIGDO_FILE="$(basename "${IMAGE_URL%.*}.jigdo")"

    download "$IMAGE_URL" "$(basename "$IMAGE_URL")"
    download "$TEMPLATE_URL" "$(basename "$TEMPLATE_URL")"

    rm -f "$ISO_FILE"
    jigdo-lite --noask "$JIGDO_FILE"

    if [ "$(readlink -f "$ISO_FILE")" != "$(readlink -f "$OUTPUT_FILE")" ]; then
        mv "$ISO_FILE" "$OUTPUT_FILE"
    fi
}


if [ "$EXTENSION" = "jigdo" ]; then
    download_jigdo "$IMAGE_URL" "$OUTPUT_FILE"
else
    download "$IMAGE_URL" "$OUTPUT_FILE"
fi
