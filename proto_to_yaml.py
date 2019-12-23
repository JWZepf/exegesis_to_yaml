import textwrap
from exegesis.proto.instructions_pb2 import ArchitectureProto
from google.protobuf import text_format


def ParseInstructionSet(instr_set, outfile, indent):
    outfile.write(indent + "- source_infos:\n")
    indent += "      "
    for source_info in instr_set.source_infos:
        ParseInstructionSourceInfo(source_info, outfile, indent)
    indent = indent[:-6]

    outfile.write(indent + "  instruction_groups:\n")
    indent += "      "
    group_index = 0
    for instr_group in instr_set.instruction_groups:
        ParseInstructionGroup(instr_group, group_index, instr_set, outfile, indent)
        group_index += 1
    indent = indent[:-6]

    return 0

def ParseInstructionSourceInfo(source_info, outfile, indent):
    outfile.write(indent + "- name: \"" + source_info.source_name + "\"\n")

    outfile.write(indent + "  metadata:\n")
    indent += "      "
    for metadata in source_info.metadata:
        outfile.write(indent + "- key: \"" + metadata.key + "\"\n")
        outfile.write(indent + "  value: \"" + metadata.value + "\"\n")
    indent = indent[:-6]

    outfile.write("\n")
    return 0

def ParseInstructionGroup(instr_group, group_index, instr_set, outfile, indent):
    outfile.write(indent + "- group_name: \"" + instr_group.name + "\"\n")
    outfile.write(indent + "  short_description: \"" + instr_group.short_description + "\"\n")
    wrapped = textwrap.wrap(instr_group.description, width=75)
    outfile.write(indent + "  description: \"\n")
    for line in wrapped:
        outfile.write(indent + "               " + line + "\n")
    outfile.write(indent + "               \"\n")

    outfile.write(indent + "  flags_affected:\n")
    indent += "      "
    for flag in instr_group.flags_affected:
        outfile.write(indent + "- content: \"" + flag.content + "\"\n")
    indent = indent[:-6]

    outfile.write(indent + "  instructions:\n")
    indent += "      "
    for instr in instr_set.instructions:
        if (instr.instruction_group_index == group_index):
            ParseInstruction(instr, outfile, indent)
    indent = indent[:-6]

    outfile.write("\n")
    return 0

def ParseInstruction(instr, outfile, indent):
    outfile.write(indent + "- description: \"" + instr.description + "\"\n")
    outfile.write(indent + "  llvm_mnemonic: \"" + instr.llvm_mnemonic + "\"\n")
    outfile.write(indent + "  feature: \"" + instr.feature_name + "\"\n")
    outfile.write(indent + "  64-bit: " + str(instr.available_in_64_bit) + "\n")
    outfile.write(indent + "  legacy_instr: " + str(instr.legacy_instruction) + "\n")
    outfile.write(indent + "  encoding_scheme: \"" + instr.encoding_scheme + "\"\n")
    outfile.write(indent + "  min_privilege_level: " + str(instr.protection_mode) + "\n")
    outfile.write(indent + "  raw_encoding_specification: \"" + instr.raw_encoding_specification + "\"\n")
    outfile.write(indent + "  x86_encoding specification: \"" + str(instr.x86_encoding_specification) + "\"\n")
    outfile.write(indent + "  fixed_size_encoding_specification: \"" + str(instr.fixed_size_encoding_specification) + "\"\n")

    outfile.write(indent + "  vendor_syntax:\n")
    indent += "      "
    for syntax in instr.vendor_syntax:
        ParseInstructionFormat(syntax, outfile, indent)
    indent = indent[:-6]

    outfile.write(indent + "  assembly_syntax:\n")
    indent += "      "
    ParseInstructionFormat(instr.syntax, outfile, indent)
    indent = indent[:-6]

    outfile.write(indent + "  att_syntax:\n")
    indent += "      "
    ParseInstructionFormat(instr.att_syntax, outfile, indent)
    indent = indent[:-6]

    outfile.write(indent + "  implicit_input_operands:\n")
    indent += "      "
    for input_operand in instr.implicit_input_operands:
        outfile.write(indent + "- operand: \"" + input_operand + "\"\n")
    indent = indent[:-6]

    outfile.write(indent + "  implicit_output_operands:\n")
    indent += "      "
    for output_operand in instr.implicit_output_operands:
        outfile.write(indent + "- operand: \"" + output_operand + "\"\n")
    indent = indent[:-6]

    outfile.write(indent + "  leaf_instructions:\n")
    indent += "      "
    for leaf in instr.leaf_instructions:
        ParseInstruction(leaf, outfile, indent)
    indent = indent[:-6]

    outfile.write("\n")
    return 0

def ParseInstructionFormat(instr_format, outfile, indent):
    outfile.write(indent + "- mnemonic: " + instr_format.mnemonic + "\n")
    outfile.write(indent + "  operands:\n")
    indent += "      "
    for operand in instr_format.operands:
        ParseInstructionOperand(operand, outfile, indent)
    indent = indent[:-6]

    return 0

def ParseInstructionOperand(operand, outfile, indent):
    addressing_mode = {
        0x0: "ANY_ADDRESSING_MODE",
        0x1: "NO_ADDRESSING",
        0x2: "ANY_ADDERSSING_WITH_FLEXIBLE_REGISTERS",
        0x21: "DIRECT_ADDRESSING",
        0x212: "BLOCK_DIRECT_ADDRESSING",
        0x22: "INDIRECT_ADDRESSING",
        0x221: "INDIRECT_ADDRESSING_WITH_BASE",
        0x222: "INDIRECT_ADDRESSING_WITH_DISPLACEMENT",
        0x223: "INDIRECT_ADDRESSING_WITH_BASE_AND_DISPLACEMENT",
        0x224: "INDIRECT_ADDRESSING_WITH_BASE_AND_INDEX",
        0x225: "INDIRECT_ADDRESSING_WITH_INDEX_AND_DISPLACEMENT",
        0x226: "INDIRECT_ADDRESSING_WITH_BASE_DISPLACEMENT_AND_INDEX",
        0x227: "INDIRECT_ADDRESSING_WITH_VSIB",
        0x228: "INDIRECT_ADDRESSING_WITH_INSTRUCTION_POINTER",
        0x3: "ANY_ADDRESSING_WITH_FIXED_REGISTERS",
        0x31: "INDIRECT_ADDRESSING_BY_RSI",
        0x32: "INDIRECT_ADDRESSING_BY_RDI",
        0x4: "LOAD_EFFECTIVE_ADDRESS"
    }

    encoding = {
        0x0: "ANY_ENCODING",
        0x1: "X86_REGISTER_ENCODING",
        0x11: "OPCODE_ENCODING",
        0x12: "MODRM_ENCODING",
        0x121: "MODRM_REG_ENCODING",
        0x122: "MODRM_RM_ENCODING",
        0x13: "VEX_ENCODING",
        0x131: "VEX_V_ENCODING",
        0x132: "VEX_SUFFIX_ENCODING",
        0x14: "EVEX_ENCODING",
        0x141: "EVEX_MASK_OPERAND_ENCODING",
        0x2: "IMPLICIT_ENCODING",
        0x21: "X86_REGISTER_EAX",
        0x22: "X86_REGISTER_EBX",
        0x23: "X86_REGISTER_RAX",
        0x24: "X86_REGISTER_RBX",
        0x25: "X86_REGISTER_RCX",
        0x26: "X86_REGISTER_RDX",
        0x3: "IMMEDIATE_VALUE_ENCODING",
        0x4: "VSIB_ENCODING",
        0x5: "X86_STATIC_PROPERTY_ENCODING"
    }

    usage = {
        0: "USAGE_UNKNOWN",
        1: "USAGE_READ",
        2: "USAGE_WRITE",
        3: "USAGE_READ_WRITE"
    }

    register_class = {
        0x0: "INVALID_REGISTER_CLASS",
        0x1: "ANY_REGISTER_CLASS",
        0x11: "GENERAL_PURPOSE_REGISTER",
        0x110: "GENERAL_PURPOSE_REGISTER_8_BIT",
        0x111: "GENERAL_PURPOSE_REGISTER_16_BIT",
        0x112: "GENERAL_PURPOSE_REGISTER_32_BIT",
        0x113: "GENERAL_PURPOSE_REGISTER_64_BIT",
        0x12: "SPECIAL_REGISTER",
        0x120: "SPECIAL_REGISTER_SEGMENT",
        0x121: "SPECIAL_REGISTER_DEBUG",
        0x122: "SPECIAL_REGISTER_CONTROL",
        0x123: "SPECIAL_REGISTER_FLAG",
        0x124: "SPECIAL_REGISTER_MEMORY",
        0x125: "SPECIAL_REGISTER_MPX_BOUNDS",
        0x13: "VECTOR_REGISTER",
        0x130: "VECTOR_REGISTER_128_BIT",
        0x131: "VECTOR_REGISTER_256_BIT",
        0x132: "VECTOR_REGISTER_512_BIT",
        0x14: "FLOATING_POINT_STACK_REGISTER",
        0x15: "MMX_STACK_REGISTER",
        0x16: "MASK_REGISTER",
        0x17: "REGISTER_BLOCK",
        0x171: "REGISTER_BLOCK_128_BIT",
        0x172: "REGISTER_BLOCK_256_BIT",
        0x173: "REGISTER_BLOCK_512_BIT"
    }

    outfile.write(indent + "- name: \"" + operand.name + "\"\n")
    outfile.write(indent + "  description: \"" + operand.description + "\"\n")
    outfile.write(indent + "  value: " + str(operand.value) + "\n")
    outfile.write(indent + "  addressing_mode: \"" + addressing_mode[operand.addressing_mode] + "\"\n")
    outfile.write(indent + "  encoding: " + encoding[operand.encoding] + "\n")
    outfile.write(indent + "  value_size_bits: " + str(operand.value_size_bits) + "\n")
    outfile.write(indent + "  usage: " + usage[operand.usage] + "\n")
    outfile.write(indent + "  register_class: " + register_class[operand.register_class] + "\n")


    dt_kind = {
        0: "UNKNOWN",
        1: "FLOATING_POINT",
        4: "STRUCT",
        5: "INTEGER",
        6: "NONE"
    }

    outfile.write(indent + "  data_type:\n")
    dt = operand.data_type
    indent += "      "
    outfile.write(indent + "- type: \"" + dt_kind[dt.kind] + "\"\n")
    outfile.write(indent + "  bit_width: " + str(dt.bit_width) + "\n")
    outfile.write(indent + "  vector_width: " + str(dt.vector_width) + "\n")
    indent = indent[:-6]

    outfile.write(indent + "  tags:\n")
    indent += "      "
    for tag in operand.tags:
        outfile.write(indent + "- name: \"" + tag.name + "\"\n")
    indent = indent[:-6]

    outfile.write("\n")
    return 0

def ParseMicroarchItinerary(arch_itinerary, outfile, indent):
    outfile.write(indent + "- microarchitecture_id: \"" + arch_itinerary.microarchitecture_id + "\"\n")

    outfile.write(indent + "  itineraries:\n")
    indent += "      "
    for itinerary in arch_itinerary.itineraries:
        ParseItinerary(itinerary, outfile, indent)
    indent = indent[:-6]

    outfile.write("\n")
    return 0

def ParseItinerary(itinerary, outfile, indent):
    outfile.write(indent + "- llvm_mnemonic: \"" + itinerary.llvm_mnemonic + "\"\n")
    outfile.write(indent + "  min_latency: " + str(itinerary.min_latency) + "\n")
    outfile.write(indent + "  max_latency: " + str(itinerary.max_latency) + "\n")
    outfile.write(indent + "  proportional_latency_per_byte: " + str(itinerary.proportional_latency_per_byte) + "\n")
    outfile.write(indent + "  latency_is_approximate: " + str(itinerary.latency_is_approximate) + "\n")
    outfile.write(indent + "  min_throughput: " + str(itinerary.min_throughput) + "\n")
    outfile.write(indent + "  max_throughput: " + str(itinerary.max_throughput) + "\n")
    outfile.write(indent + "  proportional_throughput_per_byte: " + str(itinerary.proportional_throughput_per_byte) + "\n")
    outfile.write(indent + "  num_uops_unfused_domain: " + str(itinerary.num_uops_unfused_domain) + "\n")
    outfile.write(indent + "  num_uops_fused_domain: " + str(itinerary.num_uops_fused_domain) + "\n")
    outfile.write(indent + "  standard_execution: " + str(itinerary.standard_execution) + "\n")

    outfile.write(indent + "  micro_ops:\n")
    indent += "      "
    for micro_op in itinerary.micro_ops:
        ParseMicroOperation(micro_op, outfile, indent)
    indent = indent[:-6]

    outfile.write(indent + "  throughput_observation:\n")
    indent += "      "
    ParseObservationVector(itinerary.throughput_observation, outfile, indent)
    indent = indent[:-6]

    outfile.write(indent + "  latency_observation:\n")
    indent += "      "
    ParseObservationVector(itinerary.latency_observation, outfile, indent)
    indent = indent[:-6]

    outfile.write("\n")
    return 0

def ParseMicroOperation(micro_op, outfile, indent):
    outfile.write(indent + "- port_mask:\n")
    indent += "      "
    outfile.write(indent + "- comment: \"" + micro_op.port_mask.comment + "\"\n")
    for port_number in micro_op.port_mask.port_numbers:
        outfile.write(indent + "  port_number: " + str(port_number) + "\n")
    indent = indent[:-6]

    outfile.write(indent + "  latency: " + str(micro_op.latency) + "\n")
    for dependency in micro_op.dependencies:
        outfile.write(indent + "  dependency: " + str(dependency) + "\n")
    outfile.write(indent + "  double_pumped: " + str(micro_op.double_pumped) + "\n")
    outfile.write(indent + "  likely_execution_unit: \"" + micro_op.likely_execution_unit + "\"\n")

    return 0

def ParseObservationVector(vector, outfile, indent):
    outfile.write(indent + "- observations:\n")
    indent += "      "
    for observation in vector.observations:
        outfile.write(indent + "- event_name: \"" + observation.event_name + "\"\n")
        outfile.write(indent + "  measurement: " + str(observation.measurement) + "\n")
    indent = indent[:-6]

def ParseRegisterSet(reg_set, outfile, indent):
    outfile.write(indent + "- register_groups:\n")
    indent += "      "
    for reg_group in reg_set.register_groups:
        ParseRegisterGroup(reg_group, outfile, indent)
    indent = indent[:-6]

    return 0

def ParseRegisterGroup(reg_group, outfile, indent):
    outfile.write(indent + "- group_name: \"" + reg_group.name + "\"\n")
    outfile.write(indent + "  description: \"" + reg_group.description + "\"\n")

    outfile.write(indent + "  registers:\n")
    indent += "      "
    for reg in reg_group.registers:
        ParseRegister(reg, outfile, indent)
    indent = indent[:-6]

    outfile.write("\n")
    return 0

def ParseRegister(reg, outfile, indent):
    register_class = {
        0x0: "INVALID_REGISTER_CLASS",
        0x1: "ANY_REGISTER_CLASS",
        0x11: "GENERAL_PURPOSE_REGISTER",
        0x110: "GENERAL_PURPOSE_REGISTER_8_BIT",
        0x111: "GENERAL_PURPOSE_REGISTER_16_BIT",
        0x112: "GENERAL_PURPOSE_REGISTER_32_BIT",
        0x113: "GENERAL_PURPOSE_REGISTER_64_BIT",
        0x12: "SPECIAL_REGISTER",
        0x120: "SPECIAL_REGISTER_SEGMENT",
        0x121: "SPECIAL_REGISTER_DEBUG",
        0x122: "SPECIAL_REGISTER_CONTROL",
        0x123: "SPECIAL_REGISTER_FLAG",
        0x124: "SPECIAL_REGISTER_MEMORY",
        0x125: "SPECIAL_REGISTER_MPX_BOUNDS",
        0x13: "VECTOR_REGISTER",
        0x130: "VECTOR_REGISTER_128_BIT",
        0x131: "VECTOR_REGISTER_256_BIT",
        0x132: "VECTOR_REGISTER_512_BIT",
        0x14: "FLOATING_POINT_STACK_REGISTER",
        0x15: "MMX_STACK_REGISTER",
        0x16: "MASK_REGISTER",
        0x17: "REGISTER_BLOCK",
        0x171: "REGISTER_BLOCK_128_BIT",
        0x172: "REGISTER_BLOCK_256_BIT",
        0x173: "REGISTER_BLOCK_512_BIT"
    }

    outfile.write(indent + "- name: \"" + reg.name + "\"\n")
    outfile.write(indent + "  description: \"" + reg.description + "\"\n")
    outfile.write(indent + "  lsb: " + str(reg.position_in_group.lsb) + "\n")
    outfile.write(indent + "  msb: " + str(reg.position_in_group.msb) + "\n")
    outfile.write(indent + "  class: \"" + register_class[reg.register_class] + "\"\n")
    outfile.write(indent + "  implicit_coding_only: " + str(reg.implicit_encoding_only) + "\n")
    outfile.write(indent + "  binary_encoding: " + str(hex(reg.binary_encoding)) + "\n")
    outfile.write(indent + "  feature_dependency: \"" + reg.feature_name + "\"\n")

    outfile.write(indent + "  subfields:\n")
    indent += "      "
    for subfield in reg.subfields:
        ParseRegisterSubfield(subfield, outfile, indent)
    indent = indent[:-6]

    outfile.write("\n")
    return 0

def ParseRegisterSubfield(subfield, outfile, indent):
    outfile.write(indent + "- name: \"" + subfield.name + "\"\n")
    outfile.write(indent + "  description: \"" + subfield.description + "\"\n")
    outfile.write(indent + "  lsb: " + str(subfield.bit_range.lsb) + "\n")
    outfile.write(indent + "  msb: " + str(subfield.bit_range.msb) + "\n")
    outfile.write(indent + "  feature_dependency: \"" + subfield.feature_name + "\"\n")

    outfile.write("\n")
    return 0

def main():
    try:
        infile = open("intel_instruction_sets.pbtxt")
    except:
        print("Unable to open 'intel_instruction_sets.pbtxt'")
        return 1

    proto = infile.read()
    infile.close()

    try:
        outfile = open("intel_instruction_sets.yml", "w")
    except:
        print("Unable to open 'intel_instruction_sets.yml'")
        return 1

    arch = text_format.Parse(proto, ArchitectureProto())

    indent = ""
    outfile.write(indent + "- name: \"" + arch.name + "\"\n")

    outfile.write(indent + "  instruction_set:\n")
    indent += "      "
    ParseInstructionSet(arch.instruction_set, outfile, indent)
    indent = indent[:-6]

    outfile.write(indent + "  microarchitecture_instruction_itineraries:\n")
    indent += "      "
    for itinerary in arch.per_microarchitecture_itineraries:
        ParseMicroarchItinerary(itinerary, outfile, indent)
    indent = indent[:-6]

    outfile.write(indent + "  register_set:\n")
    indent += "      "
    ParseRegisterSet(arch.register_set, outfile, indent)
    indent = indent[:-6]

    outfile.close()
    return 0

main()
