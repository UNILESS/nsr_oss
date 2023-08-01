#!/usr/bin/env python3
# -*- coding: utf-8 -*-


import os
import time
from pathlib import Path
import argparse
from typing import Dict, List, Tuple, Optional
import json
from vex_lifter import VexLifter
from bin_meta import BinMeta
from helper import FileHelper
# Do not remove this line! They need to be in __main__ namespace for jsonpickle! (For IDA)
# noinspection PyUnresolvedReferences
from disas_property import BinProperty, FuncProperty


class Config:
    db_conn: str
    sln_dir: str
    ida_path: str = ""
    r2_home: str = "/opt/homebrew/bin/radare2"

    def __init__(self, conf_file_name):
        # Try with relational path
        if not os.path.isfile(conf_file_name):
            # Try with absolute path
            base_dir: str = os.path.dirname(os.path.abspath(__file__))
            conf_file_name: str = os.path.join(base_dir, os.path.basename(conf_file_name))
            if not os.path.isfile(conf_file_name):
                # print(f"[{conf_file_name}] not found")
                raise ValueError(f"[{conf_file_name}] not found")

        # noinspection PyUnusedLocal
        conf: Dict[str, str]
        with open(conf_file_name, "rt") as f:
            conf = json.load(f)

        if "ida_path" in conf:
            self.ida_path = conf["ida_path"]
        if "r2_home" in conf:
            self.r2_home = conf["r2_home"]


def main():
    proc_start = time.monotonic()

    # Parse arguments
    parser: argparse.ArgumentParser = argparse.ArgumentParser(description="Generate strands from a binary",
                                                              epilog="Component of QuickBCC")
    parser.add_argument("bin_path", type=str, help="Path of binary to generate strands")
    parser.add_argument("dest_dir", type=str, help="Directory to save generated strands")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose mode")
    parser.add_argument("-d", "--debug", action="store_true", help="Debug mode")
    parser.add_argument("-f", "--func-list-json", type=str, help="Inspect only given functions")
    parser.add_argument("-D", "--direct-func", action="store_true", help="Export function properties directly")
    parser.add_argument("-F", "--size-filter", type=str, help="Function byte size filter range (e.g. 0x123,0x234)")
    args: argparse.Namespace = parser.parse_args()

    parse_bytes: bool = True
    if args.direct_func:
        parse_bytes = False

    # Read config.json
    conf: Config = Config("config.json")

    # Read meta json
    bin_path: str = args.bin_path
    p: Path = Path(bin_path)
    meta_json: str = str(p.with_suffix(".meta.json"))
    bin_meta: BinMeta = BinMeta(meta_json, os.path.basename(bin_path))

    # Read list of target functions
    target_func_list: List[str] = FileHelper.read_func_list_json(args.func_list_json)
    if args.verbose:
        print()
        print("[*] Target function list")
        for target_func_name in target_func_list:
            print(f"- {target_func_name}")
            print()

    # Parse byte size filter
    size_filter: Optional[Tuple[int, int]] = None
    if args.size_filter is not None:
        raw_str: str = args.size_filter
        c_idx: int = raw_str.find(",")
        if c_idx != -1:
            print("Unable to parse byte size filter")
            exit_hook(proc_start, args.verbose)
            exit(1)
        size_filter_min: int = int(raw_str[:c_idx].strip())
        size_filter_max: int = int(raw_str[c_idx+1:].strip())
        size_filter = (size_filter_min, size_filter_max)

    # Generate strands
    os.makedirs(args.dest_dir, exist_ok=True)
    lifter: VexLifter = VexLifter(bin_path, args.dest_dir, verbose=args.verbose, debug=args.debug)
    success: bool = lifter.r2_analyze_binary(conf.r2_home, target_func_list, parse_bytes)
    if not success:
        exit_hook(proc_start, args.verbose)
        exit(2)
    if args.direct_func:
        exit_hook(proc_start, args.verbose)
        exit(0)
    lifter.fit_bin_into_protobuf(bin_meta)
    lifter.generate_strands(target_func_list, size_filter, parse_bytes)
    # lifter.export_to_protobuf(args.dest_dir, bin_meta, parse_bytes)
    lifter.export_protobuf(args.dest_dir, bin_path)

    exit_hook(proc_start, args.verbose)


def exit_hook(proc_start: float, verbose: bool):
    if verbose:
        proc_end: float = time.monotonic()
        print()
        print(f"[+] gen_strands.py Running Time : {proc_end - proc_start:0.3f}s")
        print()


if __name__ == "__main__":
    main()
    exit(0)
