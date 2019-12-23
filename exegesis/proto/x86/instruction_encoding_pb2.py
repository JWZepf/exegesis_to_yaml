# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: exegesis/proto/x86/instruction_encoding.proto

import sys
_b=sys.version_info[0]<3 and (lambda x:x) or (lambda x:x.encode('latin1'))
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from google.protobuf import reflection as _reflection
from google.protobuf import symbol_database as _symbol_database
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()




DESCRIPTOR = _descriptor.FileDescriptor(
  name='exegesis/proto/x86/instruction_encoding.proto',
  package='exegesis.x86',
  syntax='proto3',
  serialized_options=None,
  serialized_pb=_b('\n-exegesis/proto/x86/instruction_encoding.proto\x12\x0c\x65xegesis.x86\"\x82\x02\n\x0bVexEncoding\"\x8d\x01\n\x0fMandatoryPrefix\x12\x17\n\x13NO_MANDATORY_PREFIX\x10\x00\x12*\n&MANDATORY_PREFIX_OPERAND_SIZE_OVERRIDE\x10\x01\x12\x19\n\x15MANDATORY_PREFIX_REPE\x10\x02\x12\x1a\n\x16MANDATORY_PREFIX_REPNE\x10\x03\"c\n\tMapSelect\x12\x19\n\x15UNDEFINED_OPERAND_MAP\x10\x00\x12\x11\n\rMAP_SELECT_0F\x10\x01\x12\x13\n\x0fMAP_SELECT_0F38\x10\x02\x12\x13\n\x0fMAP_SELECT_0F3A\x10\x03\"\xd2\x04\n\x0eLegacyEncoding\"_\n\x0fLockOrRepPrefix\x12\x19\n\x15NO_LOCK_OR_REP_PREFIX\x10\x00\x12\x0f\n\x0bLOCK_PREFIX\x10\x01\x12\x0e\n\nREP_PREFIX\x10\x02\x12\x10\n\x0cREPNE_PREFIX\x10\x03\"\xba\x01\n\x15SegmentOverridePrefix\x12\x17\n\x13NO_SEGMENT_OVERRIDE\x10\x00\x12#\n\x1f\x43S_OVERRIDE_OR_BRANCH_NOT_TAKEN\x10\x01\x12\x0f\n\x0bSS_OVERRIDE\x10\x02\x12\x1f\n\x1b\x44S_OVERRIDE_OR_BRANCH_TAKEN\x10\x03\x12\x0f\n\x0b\x45S_OVERRIDE\x10\x04\x12\x0f\n\x0b\x46S_OVERRIDE\x10\x05\x12\x0f\n\x0bGS_OVERRIDE\x10\x06\"T\n\x19OperandSizeOverridePrefix\x12\x1c\n\x18NO_OPERAND_SIZE_OVERRIDE\x10\x00\x12\x19\n\x15OPERAND_SIZE_OVERRIDE\x10\x01\"T\n\x19\x41\x64\x64ressSizeOverridePrefix\x12\x1c\n\x18NO_ADDRESS_SIZE_OVERRIDE\x10\x00\x12\x19\n\x15\x41\x44\x44RESS_SIZE_OVERRIDE\x10\x01\"v\n\x0bPrefixUsage\x12\x1b\n\x17PREFIX_USAGE_IS_UNKNOWN\x10\x00\x12\x15\n\x11PREFIX_IS_IGNORED\x10\x01\x12\x1b\n\x17PREFIX_IS_NOT_PERMITTED\x10\x02\x12\x16\n\x12PREFIX_IS_REQUIRED\x10\x03\x62\x06proto3')
)



_VEXENCODING_MANDATORYPREFIX = _descriptor.EnumDescriptor(
  name='MandatoryPrefix',
  full_name='exegesis.x86.VexEncoding.MandatoryPrefix',
  filename=None,
  file=DESCRIPTOR,
  values=[
    _descriptor.EnumValueDescriptor(
      name='NO_MANDATORY_PREFIX', index=0, number=0,
      serialized_options=None,
      type=None),
    _descriptor.EnumValueDescriptor(
      name='MANDATORY_PREFIX_OPERAND_SIZE_OVERRIDE', index=1, number=1,
      serialized_options=None,
      type=None),
    _descriptor.EnumValueDescriptor(
      name='MANDATORY_PREFIX_REPE', index=2, number=2,
      serialized_options=None,
      type=None),
    _descriptor.EnumValueDescriptor(
      name='MANDATORY_PREFIX_REPNE', index=3, number=3,
      serialized_options=None,
      type=None),
  ],
  containing_type=None,
  serialized_options=None,
  serialized_start=80,
  serialized_end=221,
)
_sym_db.RegisterEnumDescriptor(_VEXENCODING_MANDATORYPREFIX)

_VEXENCODING_MAPSELECT = _descriptor.EnumDescriptor(
  name='MapSelect',
  full_name='exegesis.x86.VexEncoding.MapSelect',
  filename=None,
  file=DESCRIPTOR,
  values=[
    _descriptor.EnumValueDescriptor(
      name='UNDEFINED_OPERAND_MAP', index=0, number=0,
      serialized_options=None,
      type=None),
    _descriptor.EnumValueDescriptor(
      name='MAP_SELECT_0F', index=1, number=1,
      serialized_options=None,
      type=None),
    _descriptor.EnumValueDescriptor(
      name='MAP_SELECT_0F38', index=2, number=2,
      serialized_options=None,
      type=None),
    _descriptor.EnumValueDescriptor(
      name='MAP_SELECT_0F3A', index=3, number=3,
      serialized_options=None,
      type=None),
  ],
  containing_type=None,
  serialized_options=None,
  serialized_start=223,
  serialized_end=322,
)
_sym_db.RegisterEnumDescriptor(_VEXENCODING_MAPSELECT)

_LEGACYENCODING_LOCKORREPPREFIX = _descriptor.EnumDescriptor(
  name='LockOrRepPrefix',
  full_name='exegesis.x86.LegacyEncoding.LockOrRepPrefix',
  filename=None,
  file=DESCRIPTOR,
  values=[
    _descriptor.EnumValueDescriptor(
      name='NO_LOCK_OR_REP_PREFIX', index=0, number=0,
      serialized_options=None,
      type=None),
    _descriptor.EnumValueDescriptor(
      name='LOCK_PREFIX', index=1, number=1,
      serialized_options=None,
      type=None),
    _descriptor.EnumValueDescriptor(
      name='REP_PREFIX', index=2, number=2,
      serialized_options=None,
      type=None),
    _descriptor.EnumValueDescriptor(
      name='REPNE_PREFIX', index=3, number=3,
      serialized_options=None,
      type=None),
  ],
  containing_type=None,
  serialized_options=None,
  serialized_start=343,
  serialized_end=438,
)
_sym_db.RegisterEnumDescriptor(_LEGACYENCODING_LOCKORREPPREFIX)

_LEGACYENCODING_SEGMENTOVERRIDEPREFIX = _descriptor.EnumDescriptor(
  name='SegmentOverridePrefix',
  full_name='exegesis.x86.LegacyEncoding.SegmentOverridePrefix',
  filename=None,
  file=DESCRIPTOR,
  values=[
    _descriptor.EnumValueDescriptor(
      name='NO_SEGMENT_OVERRIDE', index=0, number=0,
      serialized_options=None,
      type=None),
    _descriptor.EnumValueDescriptor(
      name='CS_OVERRIDE_OR_BRANCH_NOT_TAKEN', index=1, number=1,
      serialized_options=None,
      type=None),
    _descriptor.EnumValueDescriptor(
      name='SS_OVERRIDE', index=2, number=2,
      serialized_options=None,
      type=None),
    _descriptor.EnumValueDescriptor(
      name='DS_OVERRIDE_OR_BRANCH_TAKEN', index=3, number=3,
      serialized_options=None,
      type=None),
    _descriptor.EnumValueDescriptor(
      name='ES_OVERRIDE', index=4, number=4,
      serialized_options=None,
      type=None),
    _descriptor.EnumValueDescriptor(
      name='FS_OVERRIDE', index=5, number=5,
      serialized_options=None,
      type=None),
    _descriptor.EnumValueDescriptor(
      name='GS_OVERRIDE', index=6, number=6,
      serialized_options=None,
      type=None),
  ],
  containing_type=None,
  serialized_options=None,
  serialized_start=441,
  serialized_end=627,
)
_sym_db.RegisterEnumDescriptor(_LEGACYENCODING_SEGMENTOVERRIDEPREFIX)

_LEGACYENCODING_OPERANDSIZEOVERRIDEPREFIX = _descriptor.EnumDescriptor(
  name='OperandSizeOverridePrefix',
  full_name='exegesis.x86.LegacyEncoding.OperandSizeOverridePrefix',
  filename=None,
  file=DESCRIPTOR,
  values=[
    _descriptor.EnumValueDescriptor(
      name='NO_OPERAND_SIZE_OVERRIDE', index=0, number=0,
      serialized_options=None,
      type=None),
    _descriptor.EnumValueDescriptor(
      name='OPERAND_SIZE_OVERRIDE', index=1, number=1,
      serialized_options=None,
      type=None),
  ],
  containing_type=None,
  serialized_options=None,
  serialized_start=629,
  serialized_end=713,
)
_sym_db.RegisterEnumDescriptor(_LEGACYENCODING_OPERANDSIZEOVERRIDEPREFIX)

_LEGACYENCODING_ADDRESSSIZEOVERRIDEPREFIX = _descriptor.EnumDescriptor(
  name='AddressSizeOverridePrefix',
  full_name='exegesis.x86.LegacyEncoding.AddressSizeOverridePrefix',
  filename=None,
  file=DESCRIPTOR,
  values=[
    _descriptor.EnumValueDescriptor(
      name='NO_ADDRESS_SIZE_OVERRIDE', index=0, number=0,
      serialized_options=None,
      type=None),
    _descriptor.EnumValueDescriptor(
      name='ADDRESS_SIZE_OVERRIDE', index=1, number=1,
      serialized_options=None,
      type=None),
  ],
  containing_type=None,
  serialized_options=None,
  serialized_start=715,
  serialized_end=799,
)
_sym_db.RegisterEnumDescriptor(_LEGACYENCODING_ADDRESSSIZEOVERRIDEPREFIX)

_LEGACYENCODING_PREFIXUSAGE = _descriptor.EnumDescriptor(
  name='PrefixUsage',
  full_name='exegesis.x86.LegacyEncoding.PrefixUsage',
  filename=None,
  file=DESCRIPTOR,
  values=[
    _descriptor.EnumValueDescriptor(
      name='PREFIX_USAGE_IS_UNKNOWN', index=0, number=0,
      serialized_options=None,
      type=None),
    _descriptor.EnumValueDescriptor(
      name='PREFIX_IS_IGNORED', index=1, number=1,
      serialized_options=None,
      type=None),
    _descriptor.EnumValueDescriptor(
      name='PREFIX_IS_NOT_PERMITTED', index=2, number=2,
      serialized_options=None,
      type=None),
    _descriptor.EnumValueDescriptor(
      name='PREFIX_IS_REQUIRED', index=3, number=3,
      serialized_options=None,
      type=None),
  ],
  containing_type=None,
  serialized_options=None,
  serialized_start=801,
  serialized_end=919,
)
_sym_db.RegisterEnumDescriptor(_LEGACYENCODING_PREFIXUSAGE)


_VEXENCODING = _descriptor.Descriptor(
  name='VexEncoding',
  full_name='exegesis.x86.VexEncoding',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
    _VEXENCODING_MANDATORYPREFIX,
    _VEXENCODING_MAPSELECT,
  ],
  serialized_options=None,
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=64,
  serialized_end=322,
)


_LEGACYENCODING = _descriptor.Descriptor(
  name='LegacyEncoding',
  full_name='exegesis.x86.LegacyEncoding',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
    _LEGACYENCODING_LOCKORREPPREFIX,
    _LEGACYENCODING_SEGMENTOVERRIDEPREFIX,
    _LEGACYENCODING_OPERANDSIZEOVERRIDEPREFIX,
    _LEGACYENCODING_ADDRESSSIZEOVERRIDEPREFIX,
    _LEGACYENCODING_PREFIXUSAGE,
  ],
  serialized_options=None,
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=325,
  serialized_end=919,
)

_VEXENCODING_MANDATORYPREFIX.containing_type = _VEXENCODING
_VEXENCODING_MAPSELECT.containing_type = _VEXENCODING
_LEGACYENCODING_LOCKORREPPREFIX.containing_type = _LEGACYENCODING
_LEGACYENCODING_SEGMENTOVERRIDEPREFIX.containing_type = _LEGACYENCODING
_LEGACYENCODING_OPERANDSIZEOVERRIDEPREFIX.containing_type = _LEGACYENCODING
_LEGACYENCODING_ADDRESSSIZEOVERRIDEPREFIX.containing_type = _LEGACYENCODING
_LEGACYENCODING_PREFIXUSAGE.containing_type = _LEGACYENCODING
DESCRIPTOR.message_types_by_name['VexEncoding'] = _VEXENCODING
DESCRIPTOR.message_types_by_name['LegacyEncoding'] = _LEGACYENCODING
_sym_db.RegisterFileDescriptor(DESCRIPTOR)

VexEncoding = _reflection.GeneratedProtocolMessageType('VexEncoding', (_message.Message,), dict(
  DESCRIPTOR = _VEXENCODING,
  __module__ = 'exegesis.proto.x86.instruction_encoding_pb2'
  # @@protoc_insertion_point(class_scope:exegesis.x86.VexEncoding)
  ))
_sym_db.RegisterMessage(VexEncoding)

LegacyEncoding = _reflection.GeneratedProtocolMessageType('LegacyEncoding', (_message.Message,), dict(
  DESCRIPTOR = _LEGACYENCODING,
  __module__ = 'exegesis.proto.x86.instruction_encoding_pb2'
  # @@protoc_insertion_point(class_scope:exegesis.x86.LegacyEncoding)
  ))
_sym_db.RegisterMessage(LegacyEncoding)


# @@protoc_insertion_point(module_scope)
