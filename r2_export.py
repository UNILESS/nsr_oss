#!/usr/bin/env python3
# -*- coding: utf-8 -*-


import os
import re
import time
import base64
from typing import Dict, List, Any, Pattern, Optional, Match
import r2pipe
from disas_property import BinProperty, FuncProperty


TIMEOUT_SEC: int = 4 * 60


class R2Exporter:
    r2_home: str
    bin_file_name: str
    bin_file_path: str
    target_functions: List[str]
    verbose: bool
    debug: bool
    bin_prop: BinProperty
    func_prop_dict: Dict[str, FuncProperty]
    success: bool

    def __init__(self, r2_home: str, bin_file_path: str, target_functions: List[str], verbose: bool, debug: bool):
        self.r2_home = r2_home
        self.bin_file_path = bin_file_path
        self.bin_file_name = os.path.basename(self.bin_file_path)
        self.target_functions = target_functions
        self.verbose = verbose
        self.debug = debug
        self.func_prop_dict = {}
        self.success = True

    def read_functions(self, parse_bytes: bool):
        # Open a pipe with radare2 (Disable stderr messages)
        # https://r2wiki.readthedocs.io/en/latest/home/radare2-tools/
        # https://r2wiki.readthedocs.io/en/latest/home/radare2-python-scripting/
        r2_flags: List[str] = ["-2"]
        if self.debug:
            r2_flags = []
        r2: r2pipe.open = r2pipe.open(self.bin_file_path, flags=r2_flags)

        # Set timeout as 5min
        r2.cmd(f"e anal.timeout={TIMEOUT_SEC}")

        time_start: float = time.monotonic()
        try:
            # Analyze the binary
            # r2.cmd("aa")
            # r2.cmd("aac")
            # r2.cmd("aar")
            # r2.cmd("aav")
            # r2.cmd("aan")
            r2.cmd("aaa")
            if R2Exporter.check_timeout(time_start, TIMEOUT_SEC):
                self.success = False
                return

            # Get an information about a binary
            bin_info_dict: Dict[str, Any] = r2.cmdj("ij")
            bin_arch: str = bin_info_dict["bin"]["machine"]
            bin_bits: int = bin_info_dict["bin"]["bits"]
            bin_format: str = bin_info_dict["bin"]["bintype"]
            bin_be: bool = True
            if bin_info_dict["bin"]["endian"] == "little":
                bin_be = False
            bin_os: str = bin_info_dict["bin"]["os"]
            if R2Exporter.check_timeout(time_start, TIMEOUT_SEC):
                self.success = False
                return

            # Get an information about .text section
            text_min_bound: int = 0
            text_max_bound: int = 0
            text_offset: int = 0
            text_size: int = 0
            section_list: List[Dict[str, Any]] = r2.cmdj("iSj")
            for section_entry in section_list:
                section_name: str = section_entry["name"]
                if section_name != ".text":
                    continue
                text_offset = section_entry["vaddr"]
                text_size = section_entry["vsize"]
                text_min_bound = text_offset
                text_max_bound = text_offset + text_size
            if text_min_bound == 0 or text_max_bound == 0:
                print("[.text] section not found from the binary")
                exit(1)
            self.bin_prop: BinProperty = BinProperty(bin_arch, bin_bits, bin_format, bin_be, bin_os, text_offset,
                                                     text_size)
            if R2Exporter.check_timeout(time_start, TIMEOUT_SEC):
                self.success = False
                return

            # Get a list of functions
            # noinspection SpellCheckingInspection
            func_list: List[Dict[str, Any]] = r2.cmdj("aflj")
            if func_list is None:
                return
            if R2Exporter.check_timeout(time_start, TIMEOUT_SEC):
                self.success = False
                return

            # Create an instance of function property
            func_name_regex: Pattern[str] = re.compile("(?:sym\\.)(?!imp\\.)(.+)")
            func_export_regex: Pattern[str] = re.compile("(?:sym\\.)(?:.+)\\.dll_(.+)")
            func_offset_regex: Pattern[str] = re.compile("(?:fcn\\.)(.+)")
            for func_entry in func_list:
                func_name = func_entry["name"]
                func_offset = func_entry["offset"]
                func_size = func_entry["size"]
                func_call_count = func_entry["cc"]

                # Check if a function is located in .text section
                if not (text_min_bound <= func_offset < text_max_bound):
                    if self.debug:
                        print(f"- {func_name:40} : Not in .text")
                    continue

                # Check function size
                # As pyvex sometimes gets confused with very small functions
                if func_size <= 16:
                    if self.debug:
                        print(f"- {func_name:40} : <= 16B")
                    continue

                # Read real function name
                # [sym.{func_name}], [fcn.{addr}] -> Inspect
                # [sym.{filename}.dll_0x10009e70] -> Windows Export Functions
                # [loc.{any}], [loc.imp.{any}], [sym.imp.{any}] -> Ignore
                # noinspection PyUnusedLocal
                real_func_name: str
                m: Optional[Match[str]] = func_name_regex.match(func_name)
                if m is not None:
                    m2: Optional[Match[str]] = func_export_regex.match(func_name)
                    if m2 is None:  # Normal function
                        real_func_name = m.group(1)
                    else:  # Windows Export Functions, remove "{filename}.dll_".
                        real_func_name = m2.group(1)
                else:
                    m: Optional[Match[str]] = func_offset_regex.match(func_name)
                    if m is None:
                        continue
                    real_func_name = "func" + m.group(1)

                # Check if this func_entry is listed in the target_func_names
                if 0 < len(self.target_functions) and real_func_name not in self.target_functions:
                    if self.debug:
                        print(f"- {func_name:40} : Not in target function names ({real_func_name})")
                    continue

                if self.verbose:
                    print(f"- {func_name:40} : Offset {func_offset}, Size {func_size}")

                raw_bytes: Optional[bytes] = None
                if parse_bytes:
                    read_bytes_cmd: str = f"p6e {func_size} @ {func_name}"
                    func_bytes_str: str = r2.cmd(read_bytes_cmd).rstrip()
                    raw_bytes = base64.b64decode(func_bytes_str)
                    # inst_bytes must be bytes, but sometimes str is returned (unable to figure why).
                    # So check the type of inst_bytes as a quick hack.
                    if type(raw_bytes) is str:
                        continue

                func_prop: FuncProperty = FuncProperty(real_func_name, func_offset, func_size,
                                                       func_offset - text_offset,
                                                       raw_bytes, func_call_count)
                self.func_prop_dict[real_func_name] = func_prop

                if R2Exporter.check_timeout(time_start, TIMEOUT_SEC):
                    self.success = False
                    return
        except Exception as e:
            self.success = False
            print(e)
        finally:
            r2.quit()

        if self.debug:
            func_count = len(self.func_prop_dict)
            print(f"Read {func_count} functions")
        return

    @staticmethod
    def check_timeout(time_start_mono: float, timeout_sec: int) -> bool:
        time_elapsed: float = time.monotonic() - time_start_mono
        # Return True if timeout happened
        return timeout_sec < time_elapsed
