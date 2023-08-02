# -*- coding: utf-8 -*-
import hashlib
import os
import time
import json
from typing import Optional, List, Dict, Any, Tuple
import pyvex
import archinfo
import pickle
import proto_strand_pb2
from r2_export import R2Exporter
from disas_property import BinProperty, FuncProperty
from strand import VexStrand, FullStrandExtractor, PROTO_FUNC_REV, PROTO_BIN_REV, PROTO_BIN_TAG_REV
from bin_meta import BinMeta


MAX_ALLOWED_IRSB_COUNT = 2048


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
    # Protobuf
    pb_bin: proto_strand_pb2.Binary
    # Mode
    verbose_mode: bool
    debug_mode: bool

    def __init__(self, bin_file_path: str, dest_dir: str,
                 verbose: bool = False, debug: bool = False):
        self.bin_path = os.path.abspath(bin_file_path)
        self.bin_dir = os.path.dirname(self.bin_path)
        self.bin_file_name = os.path.basename(bin_file_path)
        self.bin_file_size = os.path.getsize(self.bin_path)
        self.dest_dir = os.path.abspath(dest_dir)
        self.bin_arch = None
        self.bin_arch_str = ""
        self.func_prop_dict = {}
        self.bb_addr_dict = {}
        self.strand_dict = {}
        self.pb_bin = proto_strand_pb2.Binary()
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
            self.bin_arch = archinfo.ArchARM()

        return exporter.success

    def _lift_func_to_vex(self, func_prop: FuncProperty) -> Optional[List[pyvex.IRSB]]:
        if self.bin_arch is None:
            print("Unable to detect binary's architecture")
            exit(1)

        invalid: bool = False
        call_count = 0
        irsb_list: List[pyvex.IRSB] = []
        irsb_pos = 0
        try:
            while irsb_pos < func_prop.size:
                addr = func_prop.addr + irsb_pos
                max_bytes: int = func_prop.size - irsb_pos
                irsb: pyvex.IRSB = pyvex.lift(func_prop.raw_bytes, addr, self.bin_arch, bytes_offset=irsb_pos, max_bytes=max_bytes, opt_level=1)

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

                # Encode function into protobuf
                self.add_func_to_protobuf(func_prop, strand_list, bb_addr_list, True)

                # Print progress
                if self.verbose_mode:
                    print(f"[{idx:4}/{func_count:4}] {func_name:<35}: {len(irsb_list):5} IRSB, {len(strand_list):5} strands")
            else:
                self.add_func_to_protobuf(func_prop, None, None, False)

                # Print progress
                if self.verbose_mode:
                    print(f"[{idx:4}/{func_count:4}] {func_name:<35}")

        all_end = time.monotonic()
        if self.verbose_mode:
            print(f"Stage took {all_end - all_start:1.3f}s")

    def fit_bin_into_protobuf(self, bin_meta: BinMeta):
        # Binary Information
        self.pb_bin.title = bin_meta.title
        self.pb_bin.file_name = self.bin_file_name
        self.pb_bin.file_size = self.bin_file_size
        self.pb_bin.revision = PROTO_BIN_REV
        self.pb_bin.text_offset = self.text_offset
        self.pb_bin.text_size = self.text_size

        # Binary Hash
        md5 = hashlib.md5()
        sha1 = hashlib.sha1()
        with open(self.bin_path, "rb") as f:
            buf: bytes = f.read()
            md5.update(buf)
            sha1.update(buf)
        self.pb_bin.md5 = md5.digest()
        self.pb_bin.sha1 = sha1.digest()

        # Binary Tag
        bin_tag_dict: Dict[str, Any] = {
            "revision": PROTO_BIN_TAG_REV,
            "vendor": bin_meta.vendor,
            "product": bin_meta.product,
            "version": bin_meta.version,
            "compiler_name": bin_meta.compiler_name,
            "compiler_ver": bin_meta.compiler_ver,
            "compile_opts": bin_meta.compile_opts,
            "tag": bin_meta.tag,
        }
        if self.debug_mode:
            self.pb_bin.tag = json.dumps(bin_tag_dict, sort_keys=True, indent=2)
        else:
            self.pb_bin.tag = json.dumps(bin_tag_dict)

    def add_func_to_protobuf(self, func_prop: FuncProperty, strands: Optional[List[VexStrand]], bb_addrs: Optional[List[int]], parsed_bytes: bool):
        pb_func = self.pb_bin.functions.add()
        pb_func.name = func_prop.name
        pb_func.addr = func_prop.addr
        pb_func.size = func_prop.size
        pb_func.text_offset = func_prop.text_offset
        pb_func.call_count = func_prop.call_count
        pb_func.revision = PROTO_FUNC_REV

        if parsed_bytes:
            # Strands
            pb_func.total_strand_count = len(strands)
            for strand in strands:
                pb_strand = pb_func.strands.add()
                strand.write_protobuf(pb_strand, self.debug_mode)
            # Basic Block Addresses
            for bb_addr in bb_addrs:
                pb_func.bb_addrs.append(bb_addr)

    def export_protobuf(self, dest_dir, bin_path):
        if self.verbose_mode:
            print()
            print("[Stage 3] Export protobuf into a file")

        # Save to file
        if self.verbose_mode:
            print()
            print("  Saving...", end="", flush=True)
        commit_start = time.monotonic()

        dest_file: str = os.path.join(dest_dir, f"{os.path.basename(bin_path)}.pickle")
        with open(dest_file, "wb") as f:
            # json.dump(self.pb_bin.SerializeToString(), f)
            pickle.dump(self.pb_bin.SerializeToString(), f)

        if self.verbose_mode:
            commit_end = time.monotonic()
            print(f"\r  Saved in {commit_end - commit_start:0.3f}s")
