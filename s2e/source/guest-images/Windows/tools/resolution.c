// Copyright (c) 2019 Cyberhaven
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

#include <windows.h>
#include <stdio.h>

int main(int argc, char **argv) {
    if (argc != 5) {
        printf("Usage: %s x_res y_res depth rate\n", argv[0]);
        return -1;
    }

    int xres = atoi(argv[1]);
    int yres = atoi(argv[2]);
    int depth = atoi(argv[3]);
    int rate = atoi(argv[4]);

    printf("Setting width=%d height=%d depth=%d rate=%d\n", xres, yres, depth, rate);

    DEVMODE devmode;
    memset(&devmode, 0, sizeof(devmode));

    devmode.dmPelsWidth = xres;
    devmode.dmPelsHeight = yres;
    devmode.dmBitsPerPel = depth;
    devmode.dmDisplayFrequency = rate;
    devmode.dmFields = DM_PELSWIDTH | DM_PELSHEIGHT | DM_BITSPERPEL | DM_DISPLAYFREQUENCY;
    devmode.dmSize = sizeof(DEVMODE);

    long result = ChangeDisplaySettings(&devmode, CDS_GLOBAL | CDS_UPDATEREGISTRY);
    printf("result=%ld\n", result);
    return 0;
}
