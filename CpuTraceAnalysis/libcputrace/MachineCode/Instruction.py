class Instruction:
    OP_LUI = 0x37
    OP_AUIPC = 0x17
    OP_JAL = 0x6f
    OP_JALR = 0x67
    OP_BRANCH = 0x63
    OP_LOAD = 0x03
    OP_STORE = 0x23
    OP_OP_IMM = 0x13
    OP_OP_IMM_32 = 0x1b
    OP_OP = 0x33
    OP_OP_32 = 0x3b
    OP_SYSTEM = 0x73
    OP_MADD = 0x43
    OP_MSUB = 0x47
    OP_NMSUB = 0x4b
    OP_NMADD = 0x4f
    OP_OP_FP = 0x53
    OP_LOAD_FP = 0x07
    OP_STORE_FP = 0x27
    OP_MISC_MEM = 0x0f
    OP_AMO = 0x2f

    INSN_SIZE_BYTE = 4

    def __init__(self, offset, insn, objdump_dism):
        # type: (int, int, str) -> None
        self.offset = offset
        self.insn = insn
        self.objdump_dism = objdump_dism.strip()
        self.dism_op = self.objdump_dism.split(" ")[0]

    def get_dism_op(self):
        # type: () -> str
        return self.dism_op

    def op_code(self):
        # type: () -> int
        return self.insn & 0b111_1111

    def rd(self):
        # type: () -> int
        return (self.insn >> 7) & 0b1_1111

    def rs1(self):
        # type: () -> int
        return (self.insn >> 15) & 0b1_1111

    def rs2(self):
        # type: () -> int
        return (self.insn >> 20) & 0b1_1111
