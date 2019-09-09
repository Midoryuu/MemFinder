#!/usr/bin/env python

import argparse
import sys
import time

from . import utils
from . import searcher
from . import simplekill


def args_parser():
    parser = argparse.ArgumentParser(description='Find a specific signature in one or more '
                                                 'applications using Yara rules and close '
                                                 'the applications')
    parser.add_argument('-p', action='store', dest='pid', nargs='+', type=int,
                        help='One or more PID of application to analyse. '
                             'Default: all working process PID')
    parser.add_argument('-n', action='store', dest='names', nargs='+', type=str,
                        help='One or more name of application to analyse. '
                             'Default: the PID defined or all working PID')
    parser.add_argument('-F', action='store', dest='folder',
                        help='Folder containing the yara rules.')
    parser.add_argument('-f', action='store', dest='file',
                        help='File containing the yara rules.')
    parser.add_argument('-m', action='store_true', dest='monitor',
                        help='Monitor mode, every 2 seconds look at the process defined by pid or name '
                             'with the defined rules. (loop mode)')
    parser.add_argument('-t', action='store', dest='timeout', type=int,
                        help='Timeout for each process.')
    return parser.parse_args()


def main():
    args = args_parser()
    print(args)
    pid = args.pid
    names = args.names
    folder = args.folder
    file = args.file
    timeout = args.timeout
    monitor = args.monitor
    if not isinstance(file, str) and not isinstance(folder, str):
        utils.display_error("You must specify a folder (-F) or a file (-f).")
        sys.exit(1)
    simplekiller = simplekill.SimpleKill()
    search = searcher.Searcher()
    while True:
        result = []
        if args.names is None:
            result = search.search_signature_by_pid(pid, folder, file, timeout)
        else:
            result = search.search_signature_by_name(names, folder, file, timeout)
        if result is not None and len(result) > 0:
            pid_list = [val['pid'] for val in result]
            if pid_list is not None and len(pid_list) > 0:
                print("Killing process with pid {}".format(pid_list))
                simplekiller.kill_by_pid(pid_list)
        if monitor:
            time.sleep(2)
            continue
        break


if __name__ == "__main__":
    main()
