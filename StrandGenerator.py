import os
import subprocess
import json
import shutil
import Architecture
import Matcher

from FingerPrint import FingerprintKind

from Models.ModelContext import Signature



class StrandGenerator:
    def __init__(self, binFilePath, funcNames, overwrite, verbose, debug):
        self._binFilePath = os.path.abspath(binFilePath)
        self._destDir = FileHelper.get_temp_dir()
        self._overwrite = overwrite
        self._verbose = verbose
        self._debug = debug

        self._protoFile = None

        # Create list-file of function
        if funcNames is not None:
            self._functionNames = list(funcNames)
            self._funcListJson = os.path.join(self._destDir, "func_list.json")
            with open(self._funcListJson, "w") as f:
                json.dump(self._functionNames, f)
        else:
            self._functionNames = None

        if self._debug:
            print(f"StrandGenerator.DestDir is [{self._destDir}]")

    def gen_strand_py_vex(self, bbAddrOnly, allowForceExit, sizeFilter=None):
        GenStrandPy = "gen_strand.py"
        venvFragment = os.path.join("venv", "Scripts", "python.exe") if os.name == "nt" else os.path.join("venv", "bin",
                                                                                                          "python")
        venvPython = os.path.join(LibSetup.GenStrandDir, venvFragment)
        args = [venvPython, GenStrandPy]

        if bbAddrOnly:
            args.append("-b")

        if self._functionNames:
            args.append(f"-f={self._funcListJson}")

        if self._verbose:
            args.append("-v")

        if self._debug:
            args.append("-d")

        if sizeFilter:
            args.append(f"-F={sizeFilter[0]},{sizeFilter[1]}")

        args.append(f"\"{self._binFilePath}\"")
        args.append(f"\"{self._destDir}\"")

        proc = subprocess.Popen(args, shell=True)
        exited = proc.wait(LibSetup.ForceKillAfterSecond * 1000) if not allowForceExit else proc.wait()
        exitCode = proc.returncode

        if exitCode != 0:
            print(f"Error: {GenStrandPy} exited with exit code [{exitCode}]")
        else:
            self._protoFile = os.path.join(self._destDir, "_.proto_strands")
            if not os.path.exists(self._protoFile):
                print("Error: protobuf file not found")
                self._protoFile = None

        return self._protoFile

    def get_func_addr(self):
        with open(self._protoFile, "rb") as f:
            protoBin = Protobuf.Binary()
            protoBin.ParseFromString(f.read())

        addrDict = {}
        for protoFunc in protoBin.Functions:
            fa = FuncBasicBlockAddr(protoFunc.Addr, protoFunc.Size, protoFunc.BbAddrs)
            addrDict[protoFunc.Name] = fa

        return addrDict

    def get_filtered_strands(self, kind, mark):
        if not self._protoFile:
            raise ValueError("Please run GenStrandPyVex first!")

        if kind == FingerprintKind.Normal:
            return self.filter_proto_strand(kind, self._protoFile, mark.RemovalDict if mark else None)
        elif kind == FingerprintKind.Removal:
            return self.filter_proto_strand(kind, self._protoFile, mark.RemovalDict if mark else None)
        elif kind == FingerprintKind.Addition:
            return self.filter_proto_strand(kind, self._protoFile, mark.RemovalDict if mark else None)
        else:
            raise ValueError(f"Invalid FingerprintKind [{kind}]")

    def save_signature(self, mark, patch_gen=None):
        global fpBytes, patchFpBytes
        if self._protoFile is None:
            raise Exception(f"Please run GenStrandPyVex first!")

        proto_bin = self.filter_proto_strand(FingerprintKind.Removal, self._protoFile, mark.RemovalDict)
        fpBytes = proto_bin.SerializeToString()

        fpBytes
        # TODO 저장 코드 필요
        print(fpBytes)

    def filter_proto_strand(self, kind, srcProtoFile, markDict):
        if markDict is None:
            markDict = {}

        protoBin = Protobuf.Binary()
        with open(srcProtoFile, "rb") as f:
            protoBin.ParseFromString(f.read())

        for protoFunc in protoBin.functions:
            markAddr = markDict.get(protoFunc.name, MarkAddr(True, set(), set()))

            filteredStrands = []
            for protoStrand in protoFunc.strands:
                if len(protoStrand.insts) < Matcher.Matcher.MinInstPerStrand:
                    continue

                if kind == FingerprintKind.Normal or kind == FingerprintKind.Removal:
                    if markAddr.EntireAddr or protoStrand.bb_addr in markAddr.BlockAddrSet or any(
                            stmt.addr in markAddr.BlockAddrSet for stmt in protoStrand.insts) or any(
                        stmt.addr in markAddr.InstAddrSet for stmt in protoStrand.insts):
                        filteredStrands.append(protoStrand)
                elif kind == FingerprintKind.Addition:
                    if markAddr.EntireAddr or any(stmt.addr in markAddr.InstAddrSet for stmt in protoStrand.insts):
                        filteredStrands.append(protoStrand)
                else:
                    raise ValueError(f"Invalid FingerprintKind [{kind}]")

            protoFunc.strands.clear()
            protoFunc.strands.extend(filteredStrands)

            if kind != FingerprintKind.Normal and not protoFunc.strands:
                print(f"[{protoBin.Title}] does not contain any valid {kind} marks")

        return protoBin

    def dump_proto_bin(self, kind, mark, dumpDir):
        os.makedirs(dumpDir, exist_ok=True)

        protoBin = self.get_filtered_strands(kind, mark)

        genSigDir = f"gen-sig"
        funcJsonDir = f"proto-strands"

        if kind == FingerprintKind.Removal:
            genSigDir = f"vuln-{genSigDir}"
            funcJsonDir = f"vuln-{funcJsonDir}"
        elif kind == FingerprintKind.Addition:
            genSigDir = f"patch-{genSigDir}"
            funcJsonDir = f"patch-{funcJsonDir}"

        genSigDir = os.path.join(dumpDir, genSigDir)
        funcJsonDir = os.path.join(dumpDir, funcJsonDir)

        shutil.copytree(self._destDir, genSigDir, dirs_exist_ok=True)
        filteredProtoFile = os.path.join(genSigDir, "_.filtered.proto_strands")

        with open(filteredProtoFile, "wb") as f:
            f.write(protoBin.SerializeToString())

        os.makedirs(funcJsonDir, exist_ok=True)

        for protoFunc in protoBin.Functions:
            funcJsonFile = os.path.join(funcJsonDir, protoFunc.Name) + ".txt"

            with open(funcJsonFile, "w", encoding="utf-8") as f:
                f.write(f"Strands of function [{protoFunc.Name}]\n\n")

                for protoStrand in protoFunc.Strands:
                    f.write(f"[0x{protoStrand.BbAddr:x8}]\n")
                    f.write(protoStrand.Desc)
                    f.write("\n\n")

    def cleanup_dest_dir(self):
        if os.path.exists(self._destDir):
            shutil.rmtree(self._destDir)
