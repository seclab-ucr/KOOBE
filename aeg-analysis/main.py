import argparse
import logging
import importlib
import os

Commands = dict()
logger = logging.getLogger("aeg")
logger.setLevel(logging.DEBUG)

def create_parser():
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest='cmd', help='sub-command help')

    command_dir = os.path.join("aeg", "commands")
    commands = [name[:-3] for name in os.listdir(command_dir) 
                 if name.endswith(".py") and not name.startswith("_")]
    for name in commands:
        class_name = "%sCommand" % name
        module = importlib.import_module("aeg.commands.%s" % name)
        new_class = getattr(module, class_name)
        cmd = subparsers.add_parser(name, help=new_class.__doc__)
        Commands[name] = new_class(cmd)

    return parser


if __name__ == '__main__':
    parser = create_parser()
    args = parser.parse_args()
    if args.cmd in Commands:
        Commands[args.cmd].run(args)
    else:
        parser.print_help()
