# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: exegesis/proto/cpuid.proto

import sys
_b=sys.version_info[0]<3 and (lambda x:x) or (lambda x:x.encode('latin1'))
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from google.protobuf import reflection as _reflection
from google.protobuf import symbol_database as _symbol_database
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()


from exegesis.proto.x86 import cpuid_pb2 as exegesis_dot_proto_dot_x86_dot_cpuid__pb2


DESCRIPTOR = _descriptor.FileDescriptor(
  name='exegesis/proto/cpuid.proto',
  package='exegesis',
  syntax='proto3',
  serialized_options=None,
  serialized_pb=_b('\n\x1a\x65xegesis/proto/cpuid.proto\x12\x08\x65xegesis\x1a\x1e\x65xegesis/proto/x86/cpuid.proto\"S\n\x0e\x43puIdDumpProto\x12\x39\n\x0ex86_cpuid_dump\x18\x01 \x01(\x0b\x32\x1f.exegesis.x86.X86CpuIdDumpProtoH\x00\x42\x06\n\x04\x64umpb\x06proto3')
  ,
  dependencies=[exegesis_dot_proto_dot_x86_dot_cpuid__pb2.DESCRIPTOR,])




_CPUIDDUMPPROTO = _descriptor.Descriptor(
  name='CpuIdDumpProto',
  full_name='exegesis.CpuIdDumpProto',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='x86_cpuid_dump', full_name='exegesis.CpuIdDumpProto.x86_cpuid_dump', index=0,
      number=1, type=11, cpp_type=10, label=1,
      has_default_value=False, default_value=None,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  serialized_options=None,
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
    _descriptor.OneofDescriptor(
      name='dump', full_name='exegesis.CpuIdDumpProto.dump',
      index=0, containing_type=None, fields=[]),
  ],
  serialized_start=72,
  serialized_end=155,
)

_CPUIDDUMPPROTO.fields_by_name['x86_cpuid_dump'].message_type = exegesis_dot_proto_dot_x86_dot_cpuid__pb2._X86CPUIDDUMPPROTO
_CPUIDDUMPPROTO.oneofs_by_name['dump'].fields.append(
  _CPUIDDUMPPROTO.fields_by_name['x86_cpuid_dump'])
_CPUIDDUMPPROTO.fields_by_name['x86_cpuid_dump'].containing_oneof = _CPUIDDUMPPROTO.oneofs_by_name['dump']
DESCRIPTOR.message_types_by_name['CpuIdDumpProto'] = _CPUIDDUMPPROTO
_sym_db.RegisterFileDescriptor(DESCRIPTOR)

CpuIdDumpProto = _reflection.GeneratedProtocolMessageType('CpuIdDumpProto', (_message.Message,), dict(
  DESCRIPTOR = _CPUIDDUMPPROTO,
  __module__ = 'exegesis.proto.cpuid_pb2'
  # @@protoc_insertion_point(class_scope:exegesis.CpuIdDumpProto)
  ))
_sym_db.RegisterMessage(CpuIdDumpProto)


# @@protoc_insertion_point(module_scope)