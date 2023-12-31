package io.joern.ghidra2cpg.processors

import scala.collection.mutable

object X86Processor extends Processor {
  override val getInstructions: mutable.HashMap[String, String] =
    mutable.HashMap(
      "ADC"       -> "<operator>.incBy",
      "ADD"       -> "<operator>.incBy",
      "ADDR32"    -> "<operator>.TODO",
      "ADDSD"     -> "<operator>.incBy",
      "ADDSS"     -> "<operator>.incBy",
      "AND"       -> "<operator>.assignmentAnd",
      "BSF"       -> "<operator>.TODO",
      "BSR"       -> "<operator>.TODO",
      "BSWAP"     -> "<operator>.TODO",
      "BT"        -> "<operator>.TODO",
      "BTC"       -> "<operator>.TODO",
      "BTR"       -> "<operator>.TODO",
      "BTS"       -> "<operator>.TODO",
      "CALL"      -> "CALL",
      "CDQ"       -> "<operator>.assignment",
      "CDQE"      -> "<operator>.assignment",
      "CMOVA"     -> "<operator>.assignment",
      "CMOVAE"    -> "<operator>.assignment",
      "CMOVB"     -> "<operator>.assignment",
      "CMOVBE"    -> "<operator>.assignment",
      "CMOVC"     -> "<operator>.assignment",
      "CMOVC"     -> "<operator>.assignment",
      "CMOVE"     -> "<operator>.assignment",
      "CMOVG"     -> "<operator>.assignment",
      "CMOVG"     -> "<operator>.assignment",
      "CMOVGE"    -> "<operator>.assignment",
      "CMOVGE"    -> "<operator>.assignment",
      "CMOVL"     -> "<operator>.assignment",
      "CMOVL"     -> "<operator>.assignment",
      "CMOVLE"    -> "<operator>.assignment",
      "CMOVLE"    -> "<operator>.assignment",
      "CMOVNC"    -> "<operator>.assignment",
      "CMOVNC"    -> "<operator>.assignment",
      "CMOVNE"    -> "<operator>.assignment",
      "CMOVNS"    -> "<operator>.assignment",
      "CMOVNS"    -> "<operator>.assignment",
      "CMOVNZ"    -> "<operator>.assignment",
      "CMOVNZ"    -> "<operator>.assignment",
      "CMOVP"     -> "<operator>.assignment",
      "CMOVS"     -> "<operator>.assignment",
      "CMOVS"     -> "<operator>.assignment",
      "CMOVZ"     -> "<operator>.assignment",
      "CMOVZ"     -> "<operator>.assignment",
      "CMP"       -> "<operator>.compare",
      "CMPXCHG"   -> "<operator>.TODO",
      "COMISD"    -> "<operator>.TODO",
      "COMISS"    -> "<operator>.TODO",
      "CQO"       -> "<operator>.TODO",
      "CS"        -> "<operator>.TODO",
      "CVTSI2SD"  -> "<operator>.TODO",
      "CVTSI2SD"  -> "<operator>.TODO",
      "CVTSI2SS"  -> "<operator>.TODO",
      "CVTSI2SS"  -> "<operator>.TODO",
      "CVTSS2SD"  -> "<operator>.TODO",
      "CVTTSD2SI" -> "<operator>.TODO",
      "CVTTSS2SI" -> "<operator>.TODO",
      "CVTTSS2SI" -> "<operator>.TODO",
      "DATA16"    -> "<operator>.TODO",
      "DEC"       -> "<operator>.assignment",
      "DIV"       -> "<operator>.division",
      "DIVSD"     -> "<operator>.division",
      "DIVSS"     -> "<operator>.division",
      "ENDBR64"   -> "<operator>.NOP",
      "FADD"      -> "<operator>.incBy",
      "FCOMI"     -> "<operator>.TODO",
      "FCOMIP"    -> "<operator>.TODO",
      "FDIV"      -> "<operator>.division",
      "FDIVP"     -> "<operator>.division",
      "FDIVP"     -> "<operator>.division",
      "FDIVRP"    -> "<operator>.division",
      "FILD"      -> "<operator>.TODO",
      "FISTP"     -> "<operator>.TODO",
      "FLD"       -> "<operator>.TODO",
      "FLDCW"     -> "<operator>.TODO",
      "FMUL"      -> "<operator>.multiplication",
      "FMULP"     -> "<operator>.multiplication",
      "FNINIT"    -> "<operator>.TODO",
      "FNSTCW"    -> "<operator>.TODO",
      "FSTP"      -> "<operator>.TODO",
      "FSUBR"     -> "<operator>.subtraction",
      "FUCOMI"    -> "<operator>.TODO",
      "FUCOMIP"   -> "<operator>.TODO",
      "FXCH"      -> "<operator>.TODO",
      "HLT"       -> "<operator>.NOP",
      "IDIV"      -> "<operator>.division",
      "IMUL"      -> "<operator>.multiplication",
      "INC"       -> "<operator>.assignment",
      "JA"        -> "<operator>.goto",
      "JAE"       -> "<operator>.goto",
      "JB"        -> "<operator>.goto",
      "JBE"       -> "<operator>.goto",
      "JC"        -> "<operator>.goto",
      "JE"        -> "<operator>.goto",
      "JG"        -> "<operator>.goto",
      "JGE"       -> "<operator>.goto",
      "JL"        -> "<operator>.goto",
      "JLE"       -> "<operator>.goto",
      "JMP"       -> "<operator>.goto",
      "JNC"       -> "<operator>.goto",
      "JNE"       -> "<operator>.goto",
      "JNO"       -> "<operator>.goto",
      "JNP"       -> "<operator>.goto",
      "JNS"       -> "<operator>.goto",
      "JNZ"       -> "<operator>.goto",
      "JO"        -> "<operator>.goto",
      "JP"        -> "<operator>.goto",
      "JS"        -> "<operator>.goto",
      "JZ"        -> "<operator>.goto",
      "LEA"       -> "<operator>.addressOf",
      "LEAVE"     -> "LEAVE",
      "MOV"       -> "<operator>.assignment",
      "MOV"       -> "<operator>.assignment",
      "MOVABS"    -> "<operator>.assignment",
      "MOVAPD"    -> "<operator>.assignment",
      "MOVAPS"    -> "<operator>.assignment",
      "MOVD"      -> "<operator>.assignment",
      "MOVDQA"    -> "<operator>.assignment",
      "MOVDQU"    -> "<operator>.assignment",
      "MOVDQU"    -> "<operator>.assignment",
      "MOVMSKPD"  -> "<operator>.assignment",
      "MOVQ"      -> "<operator>.assignment",
      "MOVQ"      -> "<operator>.assignment",
      "MOVSB.REP" -> "<operator>.assignment",
      "MOVSD"     -> "<operator>.assignment",
      "MOVSD"     -> "<operator>.assignment",
      "MOVSQ.REP" -> "<operator>.assignment",
      "MOVSQ.REP" -> "<operator>.assignment",
      "MOVSS"     -> "<operator>.assignment",
      "MOVSS"     -> "<operator>.assignment",
      "MOVSX"     -> "<operator>.assignment",
      "MOVSX"     -> "<operator>.assignment",
      "MOVSXD"    -> "<operator>.assignment",
      "MOVSXD"    -> "<operator>.assignment",
      "MOVUPD"    -> "<operator>.assignment",
      "MOVUPS"    -> "<operator>.assignment",
      "MOVUPS"    -> "<operator>.assignment",
      "MOVZX"     -> "<operator>.assignment",
      "MOVZX"     -> "<operator>.assignment",
      "MUL"       -> "<operator>.multiplication",
      "MULSD"     -> "<operator>.multiplication",
      "MULSS"     -> "<operator>.multiplication",
      "NEG"       -> "<operator>.negation",
      "NOP"       -> "<operator>.NOP",
      "NOT"       -> "<operator>.not",
      "OR"        -> "<operator>.or",
      "POP"       -> "<operator>.assignment",
      "PUSH"      -> "<operator>.assignment",
      "PXOR"      -> "<operator>.assignmentXor",
      "REP"       -> "<operator>.TODO",
      "RET"       -> "RET",
      "ROL"       -> "<operator>.rotateLeft",
      "ROR"       -> "<operator>.rotateRight",
      "SAR"       -> "<operator>.arithmeticShiftRight",
      "SBB"       -> "<operator>.subtraction",
      "SETA"      -> "<operator>.assignment",
      "SETB"      -> "<operator>.assignment",
      "SETBE"     -> "<operator>.assignment",
      "SETC"      -> "<operator>.assignment",
      "SETE"      -> "<operator>.assignment",
      "SETG"      -> "<operator>.assignment",
      "SETGE"     -> "<operator>.assignment",
      "SETL"      -> "<operator>.assignment",
      "SETLE"     -> "<operator>.assignment",
      "SETNC"     -> "<operator>.assignment",
      "SETNE"     -> "<operator>.assignment",
      "SETNZ"     -> "<operator>.assignment",
      "SETO"      -> "<operator>.assignment",
      "SETS"      -> "<operator>.assignment",
      "SETZ"      -> "<operator>.assignment",
      "SHL"       -> "<operator>.logicalShiftLeft",
      "SHR"       -> "<operator>.logicalShiftRight",
      "STOSD.REP" -> "<operator>.TODO",
      "STOSQ.REP" -> "<operator>.TODO",
      "SUB"       -> "<operator>.subtraction",
      "SUBSD"     -> "<operator>.subtraction",
      "SUBSS"     -> "<operator>.subtraction",
      "TEST"      -> "<operator>.compare",
      "TZCNT"     -> "<operator>.assignment",
      "UD2"       -> "<operator>.NOP",
      "XADD"      -> "<operator>.incBy",
      "XCHG"      -> "<operator>.assignment",
      "XOR"       -> "<operator>.assignmentXor"
    )
}
