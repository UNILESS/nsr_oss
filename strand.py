#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from typing import List, Set, FrozenSet, Tuple, Iterable, Optional
import pyvex
import hashlib
from enum import IntEnum, auto
from pyvex import IRStmt
import proto_strand_pb2

# Protobuf Schema Revision
PROTO_BIN_REV = 4
PROTO_BIN_TAG_REV = 2
PROTO_FUNC_REV = 4
PROTO_STRAND_REV = 2
PROTO_INST_REV = 3


class OffsetType(IntEnum):
    REG = 1
    TMP = 2
    IMM = 3
    MEMI = 4

    @staticmethod
    def to_str(value: 'OffsetType') -> str:
        """
        :param value: Enum value
        :return: Enum key
        """
        if value == OffsetType.REG:
            return "r"
        elif value == OffsetType.TMP:
            return "t"
        elif value == OffsetType.IMM:
            return ""
        elif value == OffsetType.MEMI:
            return "m"
        else:
            return str(value)


class Offset:
    offset_type: OffsetType
    bit_size: int
    value: int
    imm_type: str

    def __init__(self, offset_type: OffsetType, bit_size: int, value: int, imm_type: str = None):
        self.offset_type = offset_type
        self.bit_size = bit_size
        self.value = value
        self.imm_type = imm_type

    def __repr__(self):
        if self.offset_type == OffsetType.IMM:
            return "{0}{1}{2}".format(OffsetType.to_str(self.offset_type), self.imm_type, self.value)
        else:
            return "{0}{1}".format(OffsetType.to_str(self.offset_type), self.value)

    def __eq__(self, other):
        return self.offset_type == other.offset_type and self.value == other.value

    def __ne__(self, other):
        return self.offset_type != other.offset_type or self.value != other.value

    def __hash__(self):
        return hash(int(self.offset_type)) ^ hash(self.bit_size) ^ hash(self.value)

    def compare_type(self, y: 'Offset') -> bool:
        # Since this is an abstraction, ignore value
        return self.offset_type == y.offset_type

    def to_mem(self):
        if self.offset_type == OffsetType.IMM:
            self.offset_type = OffsetType.MEMI

    @staticmethod
    def hash_offset_tokens(offsets: Iterable['Offset']) -> List[str]:
        res: List[int] = [0, 0, 0, 0, 0]
        imm_set: Set['Offset'] = set()

        for o in offsets:
            res[int(o.offset_type)] += 1
            if o.offset_type == OffsetType.IMM:
                imm_set.add(o)

        tokens: List[str] = [f"R{res[1]}_T{res[2]}_MI{res[4]}_"]
        for io in imm_set:
            tokens.append(f"_I{io.imm_type}{io.bit_size}/{io.value}")
        return tokens

    @staticmethod
    def hash_offset_digest(offsets: Iterable['Offset']) -> bytes:
        m = hashlib.md5()
        for t in Offset.hash_offset_tokens(offsets):
            m.update(t.encode("utf-8"))
        return m.digest()


class VStmt:
    stmt: IRStmt
    idx: int
    addr: int
    def_offsets: FrozenSet[Offset]
    ref_offsets: FrozenSet[Offset]

    def __init__(self, stmt: IRStmt, idx: int, addr: int, def_offsets: Set[Offset], ref_offsets: Set[Offset]):
        self.stmt = stmt
        self.idx = idx
        self.addr = addr
        self.def_offsets = frozenset(def_offsets)  # set of Offset
        self.ref_offsets = frozenset(ref_offsets)  # set of Offset

    def __str__(self):
        return f"[{self.idx}] {str(self.stmt)}"

    def str_detail(self):
        return f"[{self.idx}] {str(self.stmt):30} <Def:{list(self.def_offsets)}> <Ref:{list(self.ref_offsets)}>"

    def __repr__(self):
        return f"[{self.idx}] {str(self.stmt):30} <Def:{list(self.def_offsets)}> <Ref:{list(self.ref_offsets)}>"

    def __hash__(self):
        return hash(self.stmt) ^ hash(self.idx) ^ hash(self.def_offsets) ^ hash(self.ref_offsets)

    def hash_str(self) -> str:
        ir_stmt_type: int = int(IRStmtTag.str_to_enum(self.stmt.tag))
        def_tokens: List[str] = Offset.hash_offset_tokens(self.def_offsets)
        ref_tokens: List[str] = Offset.hash_offset_tokens(self.ref_offsets)

        strs: List[str] = [str(ir_stmt_type), "___"]
        for t in def_tokens:
            strs.append(t)
        strs.append("___")
        for t in ref_tokens:
            strs.append(t)
        return "".join(strs)

    def hash_stmt(self) -> bytes:
        m = hashlib.md5()
        m.update(self.hash_str().encode("utf-8"))
        return m.digest()

    def write_protobuf(self, pb_inst: proto_strand_pb2.Instruction, debug: bool):
        pb_inst.index = self.idx
        pb_inst.stmt_type = int(IRStmtTag.str_to_enum(self.stmt.tag))
        pb_inst.addr = self.addr
        pb_inst.full_hash = self.hash_stmt()
        pb_inst.revision = PROTO_INST_REV
        if debug:
            pb_inst.full_str = self.hash_str()
            pb_inst.desc = self.str_detail()

    def export_protobuf(self, debug: bool) -> proto_strand_pb2.Instruction:
        pb_inst = proto_strand_pb2.Instruction()
        self.write_protobuf(pb_inst, debug)
        return pb_inst


class IRStmtTag(IntEnum):
    NOOP = 0x1E00
    IMARK = auto()
    ABIHINT = auto()
    PUT = auto()
    PUTI = auto()
    WRTMP = auto()
    STORE = auto()
    LOADG = auto()
    STOREG = auto()
    CAS = auto()
    LLSC = auto()
    DIRTY = auto()
    MBE = auto()
    EXIT = auto()

    @staticmethod
    def str_to_enum(s: str) -> 'IRStmtTag':
        if s == "Ist_NoOp":
            return IRStmtTag.NOOP
        elif s == "Ist_IMark":
            return IRStmtTag.IMARK
        elif s == "Ist_AbiHint":
            return IRStmtTag.ABIHINT
        elif s == "Ist_Put":
            return IRStmtTag.PUT
        elif s == "Ist_PutI":
            return IRStmtTag.PUTI
        elif s == "Ist_WrTmp":
            return IRStmtTag.WRTMP
        elif s == "Ist_Store":
            return IRStmtTag.STORE
        elif s == "Ist_LoadG":
            return IRStmtTag.LOADG
        elif s == "Ist_StoreG":
            return IRStmtTag.STOREG
        elif s == "Ist_CAS":
            return IRStmtTag.CAS
        elif s == "Ist_LLSC":
            return IRStmtTag.LLSC
        elif s == "Ist_Dirty":
            return IRStmtTag.DIRTY
        elif s == "Ist_MBE":
            return IRStmtTag.MBE
        elif s == "Ist_Exit":
            return IRStmtTag.EXIT
        else:
            return IRStmtTag.NONE

    @staticmethod
    def enum_to_str(e: str) -> Optional[str]:
        if e == IRStmtTag.NOOP:
            return "Ist_NoOp"
        elif e == IRStmtTag.IMARK:
            return "Ist_IMark"
        elif e == IRStmtTag.ABIHINT:
            return "Ist_AbiHint"
        elif e == IRStmtTag.PUT:
            return "Ist_Put"
        elif e == IRStmtTag.PUTI:
            return "Ist_PutI"
        elif e == IRStmtTag.WRTMP:
            return "Ist_WrTmp"
        elif e == IRStmtTag.STORE:
            return "Ist_Store"
        elif e == IRStmtTag.LOADG:
            return "Ist_LoadG"
        elif e == IRStmtTag.STOREG:
            return "Ist_StoreG"
        elif e == IRStmtTag.CAS:
            return "Ist_CAS"
        elif e == IRStmtTag.LLSC:
            return "Ist_LLSC"
        elif e == IRStmtTag.DIRTY:
            return "Ist_Dirty"
        elif e == IRStmtTag.MBE:
            return "Ist_MBE"
        elif e == IRStmtTag.EXIT:
            return "Ist_Exit"
        else:
            return None


class IRJumpKind(IntEnum):
    Ijk_INVALID = 0x1A00
    Ijk_Boring = auto()
    Ijk_Call = auto()
    Ijk_Ret = auto()
    Ijk_ClientReq = auto()
    Ijk_Yield = auto()
    Ijk_EmWarn = auto()
    Ijk_EmFail = auto()
    Ijk_NoDecode = auto()
    Ijk_MapFail = auto()
    Ijk_InvalICache = auto()
    Ijk_FlushDCache = auto()
    Ijk_NoRedir = auto()
    Ijk_SigILL = auto()
    Ijk_SigTRAP = auto()
    Ijk_SigSEGV = auto()
    Ijk_SigBUS = auto()
    Ijk_SigFPE = auto()
    Ijk_SigFPE_IntDiv = auto()
    Ijk_SigFPE_IntOvf = auto()
    Ijk_Sys_syscall = auto()
    Ijk_Sys_int32 = auto()
    Ijk_Sys_int128 = auto()
    Ijk_Sys_int129 = auto()
    Ijk_Sys_int130 = auto()
    Ijk_Sys_int145 = auto()
    Ijk_Sys_int210 = auto()
    Ijk_Sys_sysenter = auto()


class VexStrand:
    bb_addr: int
    stmts: List[VStmt]
    inputs: FrozenSet[Offset]
    outputs: FrozenSet[Offset]
    jumpkind: IRJumpKind
    tag = None

    def __init__(self, bb_addr: int, stmts: List[VStmt], inputs: FrozenSet[Offset], jumpkind: IRJumpKind):
        self.bb_addr = bb_addr
        self.stmts = stmts
        self.inputs = inputs
        self.outputs = stmts[-1].def_offsets
        self.jumpkind = jumpkind

    def __str__(self):
        str_list: List[str] = []
        if 0 < len(self.inputs):
            str_list.append("<Inputs>")
            for i in self.inputs:
                str_list.append(str(i))
        str_list.append("<Statements>")
        for stmt in self.stmts:
            str_list.append(str(stmt))
        return "\n".join(str_list)

    def str_detail(self):
        strs: List[str] = []
        # Inputs
        if 0 < len(self.inputs):
            strs.append("<Inputs>")
            inputs: List[str] = []
            for i in self.inputs:
                inputs.append(str(i))
            strs.append(", ".join(inputs))
        # Outputs
        if 0 < len(self.outputs):
            strs.append("<Outputs>")
            outputs: List[str] = []
            for i in self.outputs:
                outputs.append(str(i))
            strs.append(", ".join(outputs))
        # JumpKind
        strs.append("<JumpKind>")
        strs.append(str(self.jumpkind))
        # Statements
        strs.append("<Statements>")
        for stmt in self.stmts:
            strs.append(stmt.str_detail())
        # Statement HashStr
        strs.append("<Statements-HashStr>")
        for stmt in self.stmts:
            strs.append(f"[{stmt.idx}] {stmt.hash_str()}")
        return "\n".join(strs)

    def write_protobuf(self, pb_strand: proto_strand_pb2.Strand, debug: bool):
        pb_strand.bb_addr = self.bb_addr
        pb_strand.input_hash = Offset.hash_offset_digest(self.inputs)
        pb_strand.output_hash = Offset.hash_offset_digest(self.outputs)
        pb_strand.jumpkind = int(self.jumpkind)
        for vstmt in self.stmts:
            pb_inst = pb_strand.insts.add()
            vstmt.write_protobuf(pb_inst, debug)
        pb_strand.revision = PROTO_STRAND_REV
        if debug:
            pb_strand.desc = self.str_detail()
            pb_strand.input_str = "".join(Offset.hash_offset_tokens(self.inputs))
            pb_strand.output_str = "".join(Offset.hash_offset_tokens(self.outputs))

    def export_protobuf(self, debug: bool) -> proto_strand_pb2.Strand:
        pb_strand = proto_strand_pb2.Strand()
        self.write_protobuf(pb_strand, debug)
        return pb_strand


class FullStrandExtractor:
    irsb: pyvex.IRSB
    vstmts: List[VStmt]

    def __init__(self, irsb: pyvex.IRSB):
        """
        Create a graph from IRSB
        :type irsb: IRSB
        """
        self.irsb = irsb
        self.vstmts: List[VStmt] = []

    def extract_strands(self) -> List[VexStrand]:
        stmts: List[pyvex.IRStmt] = self.irsb.statements
        self.vstmts: List[VStmt] = []
        last_addr = self.irsb.addr
        for idx, stmt in enumerate(stmts):
            vstmt, last_addr = FullStrandExtractor.get_vstmt_from_stmt(idx, stmt, last_addr)
            self.vstmts.append(vstmt)

        # Filter out useless opcodes (IMark, AbiHint, etc)
        self.vstmts = FullStrandExtractor._filter_unnecessary_vstmts(self.vstmts)

        # Extract Strands
        strands: List[VexStrand] = self._track_stmt_def_ref_chain_reverse()
        return strands

    def _track_stmt_def_ref_chain_reverse(self) -> List[VexStrand]:
        strands: List[VexStrand] = []
        stmt_idxs: Set[int] = set(range(0, len(self.vstmts)))
        tracked_stmt_idxs: Set[int] = set()
        while len(tracked_stmt_idxs) < len(stmt_idxs):
            stmts: List[IRStmt] = []
            untracked_stmt_idxs: List[int] = sorted(stmt_idxs - tracked_stmt_idxs)
            last_stmt_idx = untracked_stmt_idxs[-1]
            last_vstmt = self.vstmts[last_stmt_idx]
            tracked_stmt_idxs.add(last_stmt_idx)
            stmts.append(last_vstmt)
            refs: Set[Offset] = set(last_vstmt.ref_offsets)
            defs: Set[Offset] = set(last_vstmt.def_offsets)
            for i in list(reversed(untracked_stmt_idxs[:-1])):
                this_info: VStmt = self.vstmts[i]
                to_be_tracked: Set[Offset] = set(this_info.def_offsets) & refs
                if len(to_be_tracked) == 0:
                    continue
                stmts.append(this_info)
                tracked_stmt_idxs.add(i)
                refs = refs | set(this_info.ref_offsets)
                defs = defs | to_be_tracked
            inputs: Set[Offset] = refs - defs
            stmts = sorted(stmts, key=lambda x: x.idx)
            strands.append(VexStrand(self.irsb.addr, stmts, frozenset(inputs), IRJumpKind[self.irsb.jumpkind]))
        return strands

    @staticmethod
    def _get_inputs_from_vstmts(vstmts):
        """
        :type vstmts: List[VStmt]
        """
        refs: Set[Offset] = set()
        defs: Set[Offset] = set()
        for vstmt in list(reversed(vstmts)):
            refs.update(vstmt.ref_offsets)
            defs.update(vstmt.def_offsets)
        inputs: Set[Offset] = refs - defs
        return inputs

    @staticmethod
    def _filter_unnecessary_stmts(stmts):
        """
        :type stmts: list[IRStmt]
        """
        new_stmts: List[IRStmt] = []
        for stmt in stmts:
            if isinstance(stmt, pyvex.IRStmt.NoOp):
                pass
            elif isinstance(stmt, pyvex.IRStmt.IMark):
                pass
            elif isinstance(stmt, pyvex.IRStmt.AbiHint):
                pass
            else:
                new_stmts.append(stmt)
        return new_stmts

    @staticmethod
    def _filter_unnecessary_vstmts(stmt_infos):
        new_infos: List[VStmt] = []
        # noinspection PyUnusedLocal
        info: VStmt
        for info in stmt_infos:
            if isinstance(info.stmt, pyvex.IRStmt.NoOp):
                pass
            elif isinstance(info.stmt, pyvex.IRStmt.IMark):
                pass
            elif isinstance(info.stmt, pyvex.IRStmt.AbiHint):
                pass
            else:
                new_infos.append(info)
        return new_infos

    @staticmethod
    def get_vstmt_from_stmt(idx: int, stmt: pyvex.IRStmt, last_addr: int) -> Tuple[VStmt, int]:
        addr: int = last_addr
        def_offsets: Set[Offset] = set()
        ref_offsets: Set[Offset] = set()
        if isinstance(stmt, pyvex.IRStmt.NoOp):
            pass
        elif isinstance(stmt, pyvex.IRStmt.IMark):
            last_addr = stmt.addr
        elif isinstance(stmt, pyvex.IRStmt.AbiHint):
            pass
        elif isinstance(stmt, pyvex.IRStmt.Put):
            """
            Write a guest register, at a fixed offset in the guest state.
            ppIRStmt output: PUT(<offset>) = <data>
                         eg. PUT(60) = t1

            offset은 guest register를 뜻함
            """
            def_offsets.add(Offset(OffsetType.REG, 32, stmt.offset))
            ref_offsets.update(FullStrandExtractor.get_offsets_from_expr(stmt.data))
        elif isinstance(stmt, pyvex.IRStmt.PutI):
            """
            Write a guest register, at a non-fixed offset in the guest state.
            x87 FPU stack, SPARC register windows, and the Itanium register files

            ppIRStmt output: PUTI<descr>[<ix>,<bias>] = <data>
            """
            # TODO: Proper support for def_offsets
            # def_offsets.append(Offset(OffsetType.REG, stmt.offset))
            ref_offsets.update(FullStrandExtractor.get_offsets_from_expr(stmt.data))
        elif isinstance(stmt, pyvex.IRStmt.WrTmp):
            """
            Assign a value to a temporary.  Note that SSA rules require
            each tmp is only assigned to once.  IR sanity checking will
            reject any block containing a temporary which is not assigned
            to exactly once.

            ppIRStmt output: t<tmp> = <data>, eg. t1 = 3
            """
            def_offsets.add(Offset(OffsetType.TMP, 32, stmt.tmp))
            ref_offsets.update(FullStrandExtractor.get_offsets_from_expr(stmt.data))
        elif isinstance(stmt, pyvex.IRStmt.Store):
            """
            Write a value to memory.  This is a normal store, not a
            Store-Conditional.  To represent a Store-Conditional,
            instead use IRStmt.LLSC.

            ARM : addr is always register
            x86 : addr에 메모리 주소가 들어갈수도 있을것 (추정)

            addr, data는 일반적으로 RdTmp expr이다.

            ppIRStmt output: ST<end>(<addr>) = <data>, eg. STle(t1) = t2
            """
            # TODO: 이거 stmt.addr를 ref로 처리하는게 맞나?
            addr_offsets: Set[Offset] = FullStrandExtractor.get_offsets_from_expr(stmt.addr)
            for ao in addr_offsets:
                ao.to_mem()
            ref_offsets.update(addr_offsets)
            ref_offsets.update(FullStrandExtractor.get_offsets_from_expr(stmt.data))
        elif isinstance(stmt, pyvex.IRStmt.StoreG):
            """
            Guarded store.  Note that this is defined to evaluate all
            expression fields (addr, data) even if the guard evaluates
            to false.

            ppIRStmt output:
              if (<guard>) ST<end>(<addr>) = <data>
            """
            # TODO: 이거 stmt.addr를 ref로 처리하는게 맞나?
            addr_offsets: Set[Offset] = FullStrandExtractor.get_offsets_from_expr(stmt.addr)
            for ao in addr_offsets:
                ao.to_mem()
            ref_offsets.update(addr_offsets)
            ref_offsets.update(FullStrandExtractor.get_offsets_from_expr(stmt.guard))
            ref_offsets.update(FullStrandExtractor.get_offsets_from_expr(stmt.data))
        elif isinstance(stmt, pyvex.IRStmt.LoadG):
            """
            Guarded load.  Note that this is defined to evaluate all
            expression fields (addr, alt) even if the guard evaluates
            to false.

            ppIRStmt output:
              t<tmp> = if (<guard>) <cvt>(LD<end>(<addr>)) else <alt>
            """
            def_offsets.add(Offset(OffsetType.TMP, 32, stmt.dst))
            ref_offsets.update(FullStrandExtractor.get_offsets_from_expr(stmt.guard))
            ref_offsets.update(FullStrandExtractor.get_offsets_from_expr(stmt.addr))
            ref_offsets.update(FullStrandExtractor.get_offsets_from_expr(stmt.alt))
        elif isinstance(stmt, pyvex.IRStmt.CAS):
            """
            Do an atomic compare-and-swap operation.  Semantics are
            described above on a comment at the definition of IRCAS.

            ppIRStmt output:
               t<tmp> = CAS<end>(<addr> :: <expected> -> <new>)
            eg
               t1 = CASle(t2 :: t3->Add32(t3,1))
               which denotes a 32-bit atomic increment
               of a value at address t2

            A double-element CAS may also be denoted, in which case <tmp>,
            <expected> and <new> are all pairs of items, separated by
            commas.
            """
            def_offsets.add(Offset(OffsetType.TMP, 32, stmt.oldHi))
            def_offsets.add(Offset(OffsetType.TMP, 32, stmt.oldLo))
            ref_offsets.update(FullStrandExtractor.get_offsets_from_expr(stmt.addr))
            ref_offsets.update(FullStrandExtractor.get_offsets_from_expr(stmt.expdHi))
            ref_offsets.update(FullStrandExtractor.get_offsets_from_expr(stmt.expdLo))
            ref_offsets.update(FullStrandExtractor.get_offsets_from_expr(stmt.dataHi))
            ref_offsets.update(FullStrandExtractor.get_offsets_from_expr(stmt.dataLo))
        elif isinstance(stmt, pyvex.IRStmt.LLSC):
            """
            Either Load-Linked or Store-Conditional, depending on
            STOREDATA.

            If STOREDATA is NULL then this is a Load-Linked, meaning
            that data is loaded from memory as normal, but a
            'reservation' for the address is also lodged in the
            hardware.

               result = Load-Linked(addr, end)

            The data transfer type is the type of RESULT (I32, I64,
            etc).  ppIRStmt output:

               result = LD<end>-Linked(<addr>), eg. LDbe-Linked(t1)

            If STOREDATA is not NULL then this is a Store-Conditional,
            hence:

               result = Store-Conditional(addr, storedata, end)

            The data transfer type is the type of STOREDATA and RESULT
            has type Ity_I1. The store may fail or succeed depending
            on the state of a previously lodged reservation on this
            address.  RESULT is written 1 if the store succeeds and 0
            if it fails.  eg ppIRStmt output:

               result = ( ST<end>-Cond(<addr>) = <storedata> )
               eg t3 = ( STbe-Cond(t1, t2) )

            Summary of rules for transfer type:
              STOREDATA == NULL (LL):
                transfer type = type of RESULT
              STOREDATA != NULL (SC):
                transfer type = type of STOREDATA, and RESULT :: Ity_I1
            """
            def_offsets.add(Offset(OffsetType.TMP, 32, stmt.result))
            ref_offsets.update(FullStrandExtractor.get_offsets_from_expr(stmt.addr))
            if stmt.storedata is not None:
                ref_offsets.update(FullStrandExtractor.get_offsets_from_expr(stmt.storedata))
        elif isinstance(stmt, pyvex.IRStmt.Dirty):
            """
            Call (possibly conditionally) a C function that has side
            effects (ie. is "dirty").  See the comments above the
            IRDirty type declaration for more information.

            ppIRStmt output:
               t<tmp> = DIRTY <guard> <effects>
                  ::: <callee>(<args>)
            eg.
               t1 = DIRTY t27 RdFX-gst(16,4) RdFX-gst(60,4)
                     ::: foo{0x380035f4}(t2)
            """
            def_offsets.add(Offset(OffsetType.TMP, 32, stmt.tmp))
            ref_offsets.update(FullStrandExtractor.get_offsets_from_expr(stmt.guard))
            for arg in stmt.args:
                ref_offsets.update(FullStrandExtractor.get_offsets_from_expr(arg))
        elif isinstance(stmt, pyvex.IRStmt.MBE):
            """
            A memory bus event - a fence, or acquisition/release of the
            hardware bus lock.  IR optimisation treats all these as fences
            across which no memory references may be moved.
            ppIRStmt output: MBusEvent-Fence,
                             MBusEvent-BusLock, MBusEvent-BusUnlock.
            """
            pass
        elif isinstance(stmt, pyvex.IRStmt.Exit):
            """
            Conditional exit from the middle of an IRSB.
            ppIRStmt output: if (<guard>) goto {<jk>} <dst>
                         eg. if (t69) goto {Boring} 0x4000AAA:I32
            If <guard> is true, the guest state is also updated by
            PUT-ing <dst> at <offsIP>.  This is done because a
            taken exit must update the guest program counter.
            """
            def_offsets.add(Offset(OffsetType.REG, 32, stmt.offsIP))
            ref_offsets.update(FullStrandExtractor.get_offsets_from_expr(stmt.guard))
            ref_offsets.update(FullStrandExtractor.get_offsets_from_expr(stmt.dst))
        return VStmt(stmt, idx, addr, def_offsets, ref_offsets), last_addr

    @staticmethod
    def get_offsets_from_expr(expr: pyvex.IRExpr) -> Set[Offset]:
        offsets: Set[Offset] = set()
        if isinstance(expr, pyvex.IRExpr.Get):
            """
            Read a guest register, at a fixed offset in the guest state.
            ppIRExpr output: GET:<ty>(<offset>), eg. GET:I32(0)
            """
            offsets.add(Offset(OffsetType.REG, 32, expr.offset))
        elif isinstance(expr, pyvex.IRExpr.GetI):
            """
            Read a guest register at a non-fixed offset in the guest
            state.  This allows circular indexing into parts of the guest
            state, which is essential for modelling situations where the
            identity of guest registers is not known until run time.  One
            example is the x87 FP register stack.
         
            ppIRExpr output: GETI<descr>[<ix>,<bias]
                         eg. GETI(128:8xI8)[t1,0]
            """
            pass
        elif isinstance(expr, pyvex.IRExpr.RdTmp):
            """
            The value held by a temporary.
            ppIRExpr output: t<tmp>, eg. t1
            """
            offsets.add(Offset(OffsetType.TMP, 32, expr.tmp))
        elif isinstance(expr, pyvex.IRExpr.Qop):
            """
            A quaternary operation.
            ppIRExpr output: <op>(<arg1>, <arg2>, <arg3>, <arg4>),
            eg. MAddF64r32(t1, t2, t3, t4)
            """
            for arg in expr.args:
                offsets.update(FullStrandExtractor.get_offsets_from_expr(arg))
        elif isinstance(expr, pyvex.IRExpr.Triop):
            """
            A ternary operation.
            ppIRExpr output: <op>(<arg1>, <arg2>, <arg3>),
            eg. MulF64(1, 2.0, 3.0)
            """
            for arg in expr.args:
                offsets.update(FullStrandExtractor.get_offsets_from_expr(arg))
        elif isinstance(expr, pyvex.IRExpr.Binop):
            """
            A binary operation.
            ppIRExpr output: <op>(<arg1>, <arg2>), eg. Add32(t1,t2)
            """
            # IROp is an enum with very many opcodes.
            # To make IROp be compared even though instructions are abstracted, treat IROp as an immediate
            # offsets.add(Offset(OffsetType.IMM, 32, expr.op_int, "O"))
            for arg in expr.args:
                offsets.update(FullStrandExtractor.get_offsets_from_expr(arg))
        elif isinstance(expr, pyvex.IRExpr.Unop):
            """
            A unary operation.
            ppIRExpr output: <op>(<arg>), eg. Neg8(t1)
            """
            for arg in expr.args:
                offsets.update(FullStrandExtractor.get_offsets_from_expr(arg))
        elif isinstance(expr, pyvex.IRExpr.Load):
            """
            A load from memory -- a normal load, not a load-linked.
            Load-Linkeds (and Store-Conditionals) are instead represented
            by IRStmt.LLSC since Load-Linkeds have side effects and so
            are not semantically valid IRExpr's.

            ppIRExpr output: LD<end>:<ty>(<addr>), eg. LDle:I32(t1)
            """
            addr_offsets: Set[Offset] = FullStrandExtractor.get_offsets_from_expr(expr.addr)
            for ao in addr_offsets:
                ao.to_mem()
            offsets.update(addr_offsets)
        elif isinstance(expr, pyvex.IRExpr.Const):
            """
            A constant-valued expression.
            ppIRExpr output: <con>, eg. 0x4:I32
            """
            # 상수 (IMM)
            bit_size: int = 32
            imm_type: str = 'I'
            if expr.con.type == 'Ity_I1':
                imm_type = 'I'
                bit_size = 1
            elif expr.con.type == 'Ity_I8':
                imm_type = 'I'
                bit_size = 8
            elif expr.con.type == 'Ity_I16':
                imm_type = 'I'
                bit_size = 16
            elif expr.con.type == 'Ity_I32':
                imm_type = 'I'
                bit_size = 32
            elif expr.con.type == 'Ity_I64':
                imm_type = 'I'
                bit_size = 64
            elif expr.con.type == 'Ity_I128':  # 128-bit scalar
                imm_type = 'I'
                bit_size = 128
            elif expr.con.type == 'Ity_F16':  # 16 bit float
                imm_type = 'F'
                bit_size = 16
            elif expr.con.type == 'Ity_F32':  # IEEE 754 float
                imm_type = 'F'
                bit_size = 32
            elif expr.con.type == 'Ity_F64':  # IEEE 754 double
                imm_type = 'F'
                bit_size = 64
            elif expr.con.type == 'Ity_D32':  # 32-bit Decimal floating point
                imm_type = 'D'
                bit_size = 32
            elif expr.con.type == 'Ity_D64':  # 64-bit Decimal floating point
                imm_type = 'D'
                bit_size = 64
            elif expr.con.type == 'Ity_D128':  # 128-bit Decimal floating point
                imm_type = 'D'
                bit_size = 128
            elif expr.con.type == 'Ity_F128':  # 128-bit floating point; implementation defined
                imm_type = 'F'
                bit_size = 128
            elif expr.con.type == 'Ity_V128':  # 128-bit SIMD
                imm_type = 'V'
                bit_size = 128
            elif expr.con.type == 'Ity_V256':  # 256-bit SIMD
                imm_type = 'V'
                bit_size = 256
            else:
                print(f"Not supported IMM type: [{expr.con.type}]")
                exit(1)
            offsets.add(Offset(OffsetType.IMM, bit_size, expr.con.value, imm_type=imm_type))
            pass
        elif isinstance(expr, pyvex.IRExpr.CCall):
            """
            A call to a pure (no side-effects) helper C function

            ppIRExpr output: <cee>(<args>):<retty>
                  eg. foo{0x80489304}(t1, t2):I32
            """
            for arg in expr.args:
                offsets.update(FullStrandExtractor.get_offsets_from_expr(arg))
        elif isinstance(expr, pyvex.IRExpr.ITE):
            """
            A ternary if-then-else operator.  It returns iftrue if cond is
            nonzero, iffalse otherwise.  Note that it is STRICT, ie. both
            iftrue and iffalse are evaluated in all cases.

            ppIRExpr output: ITE(<cond>,<iftrue>,<iffalse>),
                         eg. ITE(t6,t7,t8)
            """
            offsets.update(FullStrandExtractor.get_offsets_from_expr(expr.cond))
            offsets.update(FullStrandExtractor.get_offsets_from_expr(expr.iftrue))
            offsets.update(FullStrandExtractor.get_offsets_from_expr(expr.iffalse))
        return offsets
