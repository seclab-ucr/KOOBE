# Copyright (c) 2020, Cyberhaven
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

# Check that the ISO file contains the correct files

set -ex

ISO="$1"
APP_NAME="$2"

if [ ! -f "$ISO" ]; then
  echo $ISO does not exist
  exit 1
fi

VL=0
if 7z l "$ISO" | grep -qi admin/oct.dll; then
  VL=1
fi

if [ "$APP_NAME" = "office2019" ]; then
  VL=1
fi

# Check that we have a proper version of office
if [ "$APP_NAME" = "office2019" ]; then
  7z l "$ISO" | grep -qi Office/Data/16.0.10358.20061
elif [ $VL -eq 0 ]; then
  7z l "$ISO" | grep -qi setup.exe
  7z l "$ISO" | grep -qi office
else
  7z l "$ISO" | grep -qi admin/oct.dll
fi
