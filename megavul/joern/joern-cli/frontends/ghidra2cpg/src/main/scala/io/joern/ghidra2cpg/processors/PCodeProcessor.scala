package io.joern.ghidra2cpg.processors
import scala.collection.mutable

object PCodeProcessor extends Processor {
  override val getInstructions: mutable.HashMap[String, String] =
    mutable.HashMap(
      "BOOL_AND"          -> "<operator>.TODO",
      "BOOL_NEGATE"       -> "<operator>.TODO",
      "BOOL_OR"           -> "<operator>.or",
      "BOOL_XOR"          -> "<operator>.xor",
      "BRANCH"            -> "<operator>.goto",
      "BRANCHIND"         -> "<operator>.goto",
      "CALL"              -> "CALL",
      "CALLIND"           -> "CALL",
      "CALLOTHER"         -> "<operator>.TODO",
      "CAST"              -> "<operator>.TODO",
      "CBRANCH"           -> "<operator>.TODO",
      "COPY"              -> "<operator>.assignment",
      "CPOOLREF"          -> "<operator>.TODO",
      "EXTRACT"           -> "<operator>.TODO",
      "FLOAT_ABS"         -> "<operator>.TODO",
      "FLOAT_ADD"         -> "<operator>.addition",
      "FLOAT_CEIL"        -> "<operator>.TODO",
      "FLOAT_DIV"         -> "<operator>.TODO",
      "FLOAT_EQUAL"       -> "<operator>.TODO",
      "FLOAT_FLOAT2FLOAT" -> "<operator>.TODO",
      "FLOAT_FLOOR"       -> "<operator>.TODO",
      "FLOAT_INT2FLOAT"   -> "<operator>.TODO",
      "FLOAT_LESS"        -> "<operator>.TODO",
      "FLOAT_LESSEQUAL"   -> "<operator>.TODO",
      "FLOAT_MULT"        -> "<operator>.TODO",
      "FLOAT_NAN"         -> "<operator>.TODO",
      "FLOAT_NEG"         -> "<operator>.TODO",
      "FLOAT_NOTEQUAL"    -> "<operator>.TODO",
      "FLOAT_ROUND"       -> "<operator>.TODO",
      "FLOAT_SQRT"        -> "<operator>.TODO",
      "FLOAT_SUB"         -> "<operator>.TODO",
      "FLOAT_TRUNC"       -> "<operator>.TODO",
      "INDIRECT"          -> "<operator>.TODO",
      "INSERT"            -> "<operator>.TODO",
      "INT_2COMP"         -> "<operator>.TODO",
      "INT_ADD"           -> "<operator>.addition",
      "INT_AND"           -> "<operator>.TODO",
      "INT_CARRY"         -> "<operator>.TODO",
      "INT_DIV"           -> "<operator>.division",
      "INT_EQUAL"         -> "<operator>.TODO",
      "INT_LEFT"          -> "<operator>.TODO",
      "INT_LESS"          -> "<operator>.TODO",
      "INT_LESSEQUAL"     -> "<operator>.TODO",
      "INT_MULT"          -> "<operator>.multiplication",
      "INT_NEGATE"        -> "<operator>.TODO",
      "INT_NOTEQUAL"      -> "<operator>.TODO",
      "INT_OR"            -> "<operator>.or",
      "INT_REM"           -> "<operator>.TODO",
      "INT_RIGHT"         -> "<operator>.TODO",
      "INT_SBORROW"       -> "<operator>.TODO",
      "INT_SCARRY"        -> "<operator>.TODO",
      "INT_SDIV"          -> "<operator>.TODO",
      "INT_SEXT"          -> "<operator>.TODO",
      "INT_SLESS"         -> "<operator>.TODO",
      "INT_SLESSEQUAL"    -> "<operator>.TODO",
      "INT_SREM"          -> "<operator>.TODO",
      "INT_SRIGHT"        -> "<operator>.TODO",
      "INT_SUB"           -> "<operator>.TODO",
      "INT_XOR"           -> "<operator>.xor",
      "INT_ZEXT"          -> "<operator>.TODO",
      "LOAD"              -> "<operator>.TODO",
      "MULTIEQUAL"        -> "<operator>.TODO",
      "NEW"               -> "<operator>.TODO",
      "PCODE_MAX"         -> "<operator>.TODO",
      "PIECE"             -> "<operator>.TODO",
      "POPCOUNT"          -> "<operator>.TODO",
      "PTRADD"            -> "<operator>.TODO",
      "PTRSUB"            -> "<operator>.TODO",
      "RETURN"            -> "RETURN",
      "SEGMENTOP"         -> "<operator>.TODO",
      "STORE"             -> "<operator>.assignment",
      "SUBPIECE"          -> "<operator>.TODO",
      "UNIMPLEMENTED"     -> "<operator>.TODO"
    )
}