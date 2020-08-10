/*
 * S2E Selective Symbolic Execution Platform
 *
 * Copyright (c) 2017, Dependable Systems Laboratory, EPFL
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include <s2e/s2e.h>
#include <s2e/decree/decree_monitor.h>

/*
 * Set to 1 if the `DecreeMonitor` plugin is enabled.
 *
 * This flag is set/unset whenever the `s2e` kernel module is loaded. This
 * avoids any issues with snapshots. For example, if the `DecreeMonitor` plugin
 * check is only made during kernel boot, then snapshots will render this check
 * useless (e.g. you might boot the kernel with the `DecreeMonitor` plugin
 * disabled but start the snapshot with it enabled).
 */
char s2e_decree_monitor_enabled = 0;
EXPORT_SYMBOL(s2e_decree_monitor_enabled);
