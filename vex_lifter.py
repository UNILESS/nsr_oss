# -*- coding: utf-8 -*-
import hashlib
import os
import time
import json
import pyvex
import archinfo

from typing import Optional, List, Dict, Any, Tuple

import pickle
from r2_export import R2Exporter
from disas_property import BinProperty, FuncProperty
from strand import VexStrand, FullStrandExtractor, PROTO_FUNC_REV, PROTO_BIN_REV, PROTO_BIN_TAG_REV
from bin_meta import BinMeta

MAX_ALLOWED_IRSB_COUNT = 2048

read_elf_path = "readelf"


class VexLifter:
    # Path
    bin_path: str
    bin_dir: str
    bin_file_name: str
    bin_file_size: int
    dest_dir: str
    # Binary Information
    bin_arch: Optional[archinfo.Arch]
    bin_arch_str: str
    bin_format: str
    bin_be: bool
    text_offset: int
    text_size: int
    # Store Strands
    func_prop_dict: Dict[str, FuncProperty]
    # Mode
    verbose_mode: bool
    debug_mode: bool

    def __init__(self, bin_file_path: str, dest_dir: str,
                 verbose: bool = False, debug: bool = False):
        self.bin_path = bin_file_path
        self.bin_dir = os.path.dirname(self.bin_path)
        self.bin_file_name = os.path.basename(bin_file_path)
        self.bin_file_size = (os.path.getsize(bin_file_path.replace('"', '')))
        self.dest_dir = os.path.abspath(dest_dir)
        self.bin_arch = None
        self.bin_arch_str = ""
        self.func_prop_dict = {}
        self.bb_addr_dict = {}
        self.strand_dict = {}
        self.verbose_mode = verbose
        self.debug_mode = debug

    def r2_analyze_binary(self, r2_home: str, target_functions: Optional[List[str]] = None, parse_bytes: bool = True):
        if target_functions is None:
            target_functions = []

        exporter: R2Exporter = R2Exporter(r2_home, self.bin_path, target_functions,
                                          verbose=self.verbose_mode,
                                          debug=self.debug_mode)
        exporter.read_functions(parse_bytes)
        success: bool = exporter.success
        if not success:
            return False

        self.func_prop_dict = exporter.func_prop_dict
        if self.debug_mode:
            read_func_list = os.path.join(self.dest_dir, "read_func_list.txt")
            with open(read_func_list, "wt") as f:
                f.writelines(self.func_prop_dict.keys())

        bin_prop: BinProperty = exporter.bin_prop
        self.text_offset = bin_prop.text_offset
        self.text_size = bin_prop.text_size
        self.bin_format = bin_prop.format
        self.bin_be = bin_prop.be
        self.bin_arch_str = bin_prop.arch
        self.THUMB = False
        if self.bin_arch_str == "AMD x86-64 architecture":  # ELF
            self.bin_arch = archinfo.ArchAMD64()
        elif self.bin_arch_str == "AMD 64":  # PE
            self.bin_arch = archinfo.ArchAMD64()
        elif self.bin_arch_str == "Intel 80386":  # ELF
            self.bin_arch = archinfo.ArchX86()
        elif self.bin_arch_str == "i386":  # PE
            self.bin_arch = archinfo.ArchX86()
        elif "MIPS" in self.bin_arch_str:
            if self.bin_be:
                self.bin_arch = archinfo.ArchMIPS32(endness=archinfo.Endness.BE)
            else:
                self.bin_arch = archinfo.ArchMIPS32(endness=archinfo.Endness.LE)
        elif self.bin_arch_str == "ARM":
            if "Thumb-2" in os.popen(f'{read_elf_path} -A {self.bin_path}').read():
                print("Thumb-2")
                self.bin_arch = archinfo.ArchARMCortexM()
                self.THUMB = True
            else:
                self.bin_arch = archinfo.ArchARM()
        elif self.bin_arch_str == "ARM aarch64":
            self.bin_arch = archinfo.ArchAArch64()
        return exporter.success

    def _lift_func_to_vex(self, func_prop: FuncProperty) -> Optional[List[pyvex.IRSB]]:
        if self.bin_arch is None:
            print("Unable to detect binary's architecture")
            exit(1)

        invalid: bool = False
        call_count = 0
        irsb_list: List[pyvex.IRSB] = []
        irsb_pos = 0
        thumb = 0
        if self.THUMB:
            thumb = 1
            func_prop.addr += 1
        try:
            while irsb_pos < func_prop.size:

                addr = func_prop.addr + irsb_pos
                max_bytes: int = func_prop.size - irsb_pos
                irsb: pyvex.IRSB = pyvex.lift(func_prop.raw_bytes, addr, self.bin_arch, bytes_offset=irsb_pos + thumb,
                                              max_bytes=max_bytes, opt_level=1)
                if irsb.size == 0:
                    break
                if irsb.jumpkind == "Ijk_NoDecode":
                    break
                if irsb.jumpkind == "Ijk_Call":
                    call_count += 1

                irsb_list.append(irsb)
                irsb_pos += irsb.size

                if MAX_ALLOWED_IRSB_COUNT < len(irsb_list):
                    invalid = True
                    break
        except:
            pass

        if invalid:
            return None
        else:
            func_prop.call_count = call_count
            return irsb_list

    @staticmethod
    def _export_vex(irsb_list: List[pyvex.IRSB], dest_file: str):
        with open(dest_file, "wt") as fp:
            for irsb in irsb_list:
                # noinspection PyProtectedMember
                fp.write(irsb._pp_str() + '\n')

    def generate_strands(self, func_list: List[str], size_filter: Optional[Tuple[int, int]], parse_bytes: bool):
        bin_dir = os.path.join('sample', self.bin_dir)

        # Print what we are doing
        if self.verbose_mode:
            print()
            path_to_print = os.path.join(bin_dir, self.bin_file_name)
            print(f"[+] Analyzing binary [{path_to_print}]")
        all_start = time.monotonic()

        if self.verbose_mode:
            print()
            print("[Stage 2] Lift to VEX, extract strands")

        idx: int = 0
        func_count = len(self.func_prop_dict)
        # noinspection PyUnusedLocal
        func_name: str  # Name of the function
        # noinspection PyUnusedLocal
        func_prop: FuncProperty  # function's properties
        for func_name, func_prop in sorted(self.func_prop_dict.items()):
            idx += 1

            # Ignore functions which were not listed
            if 0 < len(func_list) and func_name not in func_list:
                continue
            # Check binary filter size
            if size_filter is not None:
                if not (size_filter[0] <= func_prop.size <= size_filter[1]):
                    continue

            if parse_bytes:
                # Convert machine code into VEX
                irsb_list: List[pyvex.IRSB] = self._lift_func_to_vex(func_prop)
                if irsb_list is None:
                    # Sometimes pyvex fails to properly handle extremely small functions
                    continue
                # Collect basic block address
                bb_addr_list: List[int] = []
                irsb: pyvex.IRSB
                for irsb in irsb_list:
                    bb_addr_list.append(irsb.addr)
                # self.bb_addr_dict[func_name] = bb_addr_list

                # Extract FullStrand from IRSB
                strand_list: List[VexStrand] = []
                for irsb in irsb_list:
                    extractor = FullStrandExtractor(irsb)
                    strands: List[VexStrand] = extractor.extract_strands()
                    strand_list.extend(strands)

                # Encode function into pickle
                self.add_func_to_json(func_prop, strand_list, bb_addr_list, True)

                # Print progress
                if self.verbose_mode:
                    print(
                        f"[{idx:4}/{func_count:4}] {func_name:<35}: {len(irsb_list):5} IRSB, {len(strand_list):5} strands")
            else:
                self.add_func_to_json(func_prop, None, None, False)

                # Print progress
                if self.verbose_mode:
                    print(f"[{idx:4}/{func_count:4}] {func_name:<35}")

        all_end = time.monotonic()
        if self.verbose_mode:
            print(f"Stage took {all_end - all_start:1.3f}s")

    def fit_bin_into_pickle(self, bin_meta: BinMeta):

        # Binary Hash
        with open(self.bin_path.replace('"', ''), "rb") as f:
            buf: bytes = f.read()

    def add_func_to_json(self, func_prop: FuncProperty, strands: Optional[List[VexStrand]],
                         bb_addrs: Optional[List[int]], parsed_bytes: bool):
        # 복잡한 객체를 json 직렬화 가능한 형태로 변환하는 코드가 필요합니다.
        # 예를 들어, VexStrand 객체는 직렬화할 수 없습니다.
        # strands 변수를 직렬화 가능한 형태로 변환하도록 코드를 추가해야 합니다.

        func_data = {
            'name': func_prop.name,
            'addr': func_prop.addr,
            'size': func_prop.size,
            'text_offset': func_prop.text_offset,
            'call_count': func_prop.call_count,
            'revision': PROTO_FUNC_REV,
            'strands': [str(s) for s in strands] if parsed_bytes else None,  # 예시로 str() 사용
            'bb_addrs': bb_addrs if parsed_bytes else None
        }

        func_dir = os.path.join(self.dest_dir, os.path.basename(self.bin_path))
        os.makedirs(func_dir, exist_ok=True)

        func_file = os.path.join(func_dir, f"{func_prop.name}.json")
        with open(func_file, 'w') as file:
            json.dump(func_data, file)

    def export_json(self, dest_dir):
        if self.verbose_mode:
            print()
            print("[Stage 3] Export json into a file")

        # Save to file
        if self.verbose_mode:
            print()
            print("  Saving...", end="", flush=True)
        commit_start = time.monotonic()

        dest_file: str = os.path.join(dest_dir, "_.json_strands")
        with open(dest_file.replace('"', ''), "w") as f:
            json.dump(self.func_prop_dict, f)

        if self.verbose_mode:
            commit_end = time.monotonic()
            print(f"\r  Saved in {commit_end - commit_start:0.3f}s")

    def add_func_to_pickle(self, func_prop: FuncProperty, strands: Optional[List[VexStrand]],
                           bb_addrs: Optional[List[int]], parsed_bytes: bool):
        func_data = {
            'name': func_prop.name,
            'addr': func_prop.addr,
            'size': func_prop.size,
            'text_offset': func_prop.text_offset,
            'call_count': func_prop.call_count,
            'revision': PROTO_FUNC_REV,
            'strands': strands if parsed_bytes else None,
            'bb_addrs': bb_addrs if parsed_bytes else None
        }

        func_dir = os.path.join(self.dest_dir, os.path.basename(self.bin_path))
        os.makedirs(func_dir, exist_ok=True)

        func_file = os.path.join(func_dir, f"{func_prop.name}.pickle")
        with open(func_file, 'wb') as file:
            pickle.dump(func_data, file)

    def export_pickle(self, dest_dir):
        if self.verbose_mode:
            print()
            print("[Stage 3] Export pickle into a file")

        # Save to file
        if self.verbose_mode:
            print()
            print("  Saving...", end="", flush=True)
        commit_start = time.monotonic()

        dest_file: str = os.path.join(dest_dir, "_.pickle_strands")
        with open(dest_file.replace('"', ''), "wb") as f:
            pickle.dump(self.func_prop_dict, f)

        if self.verbose_mode:
            commit_end = time.monotonic()
            print(f"\r  Saved in {commit_end - commit_start:0.3f}s")