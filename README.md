# KOOBE
Towards Facilitating Exploit Generation of Kernel Out-Of-Bounds Write Vulnerabilities

## Setup
```
./setup.sh
./build.sh
```

It's been tested on Ubuntu 18.04.

## Usage
```
source koobe/bin/activate
cd aeg-analysis
python main.py -h
```

### Tutorial
1. [CVE-2017-7308](aeg-analysis/testcases/CVE-2017-7308)
2. [CVE-2018-5703](aeg-analysis/testcases/CVE-2018-5703)
3. [CVE-2017-7533](aeg-analysis/testcases/CVE-2017-7533)
4. [CVE-2017-1000112](aeg-analysis/testcases/CVE-2017-1000112)
5. [Utility](aeg-analysis)

### Build Image with Different Kernel Version
Check [this](s2e/source/s2e/s2e-linux-kernel/README.md) and [S2E's doc](s2e/source/s2e-linux-kernel/README.md).


