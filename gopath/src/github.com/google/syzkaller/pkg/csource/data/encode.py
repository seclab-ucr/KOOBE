
import os
import sys
import json

def extract(value):
    if not isinstance(value, str):
        return None
    if value.startswith("[[") and value.endswith("]]"):
        return value[2:-2]
    return None

def load(dirpath, name):
    if not name.endswith(".dat"):
        return
    print("Checking %s" % name)

    with open(os.path.join(dirpath, name), "r") as fp:
        obj = json.load(fp)
        for k, v in obj.items():
            code = extract(v)
            if code is None:
                continue
            with open(os.path.join(dirpath, "%s.snippet" % code), "r") as f:
                obj[k] = f.read()

        name = name[:-4]
        with open(os.path.join(dirpath, "%s.json" % name), "w") as f:
            json.dump(obj, f, indent=2)

def run(dirpath):
    for name in os.listdir(dirpath):
        filepath = os.path.join(dirpath, name)
        if os.path.isdir(filepath):
            run(filepath)

        load(dirpath, name)

def main():
    run(".")
    return 0

if __name__ == '__main__':
    sys.exit(main())
