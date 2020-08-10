# aeg-analysis

# Pahole
We provide a functionality to search suitable target objects with the help of pahole.
Try `python main.py pahole -h` to see the details.

For example, if we have a vulnerability allowing overwriting the first few bytes of the target object, we could use the following command to search for such objects:
```
python main.py pahole --filter_offset 0 -i /path/to/vmlinux
```

To make heap Feng Shui easier, we may want to restrict the size of the target, thus we could try:
```
python main.py pahole -s N --filter_offset 0 -i /path/to/vmlinux
```

# Parselog
All the debugging information was logged into files, and thus we could use this command to parse them for debugging purpose. For instance, we could record the execution trace by setting the following option in `s2e-config.lua` on the path `KOOBE/s2e/projects/PROJECT_NAME`:
```
pluginsConfig.PcMonitor = {
    recordTrace = true
}
```
After execution (by `./launch-s2e.sh`), a log file named `KernelExecutionTracer.dat` would be created and can be found in the directory `KOOBE/s2e/projects/PROJECT_NAME/s2e-last`. To get readable output, we can use the following command to convert raw data:
```
python main.py parselog -p PROJECT_NAME -t > trace
```

If we want to know what objects were allocated or released during the course of the execution, we could also enable the following option:
```
pluginsConfig.OptionsManager = {
    track_object = true
}
```

Then, we can execute `python main.py parselog -p PROJECT_NAME -o --reserve`, which shows allocation and release of objects in order.

## Eliminate Unnecessary Constraints
Due to concretization, a lot of unnecessary constraints may be introduced to affect the performance considerablely and sometimes prevent generating exploits. If we fail to find any solution, we could investigate where all those constraints are introduced and then complement the blacklist(`aeg-analysis/template/functions.json`) to avoid them. In the case where those constraints are necessary but too complex for symbolic execution, we have to manually implement corresponding function models like any other symbolic execution tools (e.g., KLEE, Angr).

The following command show the distribution of all the constraints we collected along the execution.
```
python main.py parselog -p PROJECT_NAME --constraint /path/to/vmlinux
```

