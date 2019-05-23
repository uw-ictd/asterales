# -*- coding: utf-8 -*-
# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: storage.proto

import sys
_b=sys.version_info[0]<3 and (lambda x:x) or (lambda x:x.encode('latin1'))
from google.protobuf.internal import enum_type_wrapper
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from google.protobuf import reflection as _reflection
from google.protobuf import symbol_database as _symbol_database
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()




DESCRIPTOR = _descriptor.FileDescriptor(
  name='storage.proto',
  package='asterales.storage',
  syntax='proto3',
  serialized_options=None,
  serialized_pb=_b('\n\rstorage.proto\x12\x11\x61sterales.storage\"G\n\x0f\x43ommunityServer\x12\n\n\x02id\x18\x01 \x01(\x03\x12\x12\n\nverify_key\x18\x02 \x01(\x0c\x12\x14\n\x0c\x64isplay_name\x18\x11 \x01(\t\"W\n\x04User\x12\n\n\x02id\x18\x01 \x01(\x03\x12\x12\n\nverify_key\x18\x02 \x01(\x0c\x12\x19\n\x11home_community_id\x18\x03 \x01(\x0c\x12\x14\n\x0c\x64isplay_name\x18\x11 \x01(\t\"\xad\x02\n\x0e\x45xchangeRecord\x12\x11\n\tsender_id\x18\x01 \x01(\x03\x12\x13\n\x0breceiver_id\x18\x02 \x01(\x03\x12$\n\x1creceiver_sequence_number_lsb\x18\x03 \x01(\x04\x12$\n\x1creceiver_sequence_number_msb\x18\x04 \x01(\x04\x12\x0e\n\x06\x61mount\x18\x05 \x01(\x03\x12-\n\x08\x63urrency\x18\x06 \x01(\x0e\x32\x1b.asterales.storage.Currency\x12\x33\n+receiver_previous_valid_sequence_number_lsb\x18\x07 \x01(\x04\x12\x33\n+receiver_previous_valid_sequence_number_msb\x18\x08 \x01(\x04*-\n\x08\x43urrency\x12\x0b\n\x07UNKNOWN\x10\x00\x12\x0b\n\x07NETWORK\x10\x01\x12\x07\n\x03USD\x10\x02\x62\x06proto3')
)

_CURRENCY = _descriptor.EnumDescriptor(
  name='Currency',
  full_name='asterales.storage.Currency',
  filename=None,
  file=DESCRIPTOR,
  values=[
    _descriptor.EnumValueDescriptor(
      name='UNKNOWN', index=0, number=0,
      serialized_options=None,
      type=None),
    _descriptor.EnumValueDescriptor(
      name='NETWORK', index=1, number=1,
      serialized_options=None,
      type=None),
    _descriptor.EnumValueDescriptor(
      name='USD', index=2, number=2,
      serialized_options=None,
      type=None),
  ],
  containing_type=None,
  serialized_options=None,
  serialized_start=502,
  serialized_end=547,
)
_sym_db.RegisterEnumDescriptor(_CURRENCY)

Currency = enum_type_wrapper.EnumTypeWrapper(_CURRENCY)
UNKNOWN = 0
NETWORK = 1
USD = 2



_COMMUNITYSERVER = _descriptor.Descriptor(
  name='CommunityServer',
  full_name='asterales.storage.CommunityServer',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='id', full_name='asterales.storage.CommunityServer.id', index=0,
      number=1, type=3, cpp_type=2, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='verify_key', full_name='asterales.storage.CommunityServer.verify_key', index=1,
      number=2, type=12, cpp_type=9, label=1,
      has_default_value=False, default_value=_b(""),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='display_name', full_name='asterales.storage.CommunityServer.display_name', index=2,
      number=17, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
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
  ],
  serialized_start=36,
  serialized_end=107,
)


_USER = _descriptor.Descriptor(
  name='User',
  full_name='asterales.storage.User',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='id', full_name='asterales.storage.User.id', index=0,
      number=1, type=3, cpp_type=2, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='verify_key', full_name='asterales.storage.User.verify_key', index=1,
      number=2, type=12, cpp_type=9, label=1,
      has_default_value=False, default_value=_b(""),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='home_community_id', full_name='asterales.storage.User.home_community_id', index=2,
      number=3, type=12, cpp_type=9, label=1,
      has_default_value=False, default_value=_b(""),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='display_name', full_name='asterales.storage.User.display_name', index=3,
      number=17, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
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
  ],
  serialized_start=109,
  serialized_end=196,
)


_EXCHANGERECORD = _descriptor.Descriptor(
  name='ExchangeRecord',
  full_name='asterales.storage.ExchangeRecord',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='sender_id', full_name='asterales.storage.ExchangeRecord.sender_id', index=0,
      number=1, type=3, cpp_type=2, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='receiver_id', full_name='asterales.storage.ExchangeRecord.receiver_id', index=1,
      number=2, type=3, cpp_type=2, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='receiver_sequence_number_lsb', full_name='asterales.storage.ExchangeRecord.receiver_sequence_number_lsb', index=2,
      number=3, type=4, cpp_type=4, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='receiver_sequence_number_msb', full_name='asterales.storage.ExchangeRecord.receiver_sequence_number_msb', index=3,
      number=4, type=4, cpp_type=4, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='amount', full_name='asterales.storage.ExchangeRecord.amount', index=4,
      number=5, type=3, cpp_type=2, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='currency', full_name='asterales.storage.ExchangeRecord.currency', index=5,
      number=6, type=14, cpp_type=8, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='receiver_previous_valid_sequence_number_lsb', full_name='asterales.storage.ExchangeRecord.receiver_previous_valid_sequence_number_lsb', index=6,
      number=7, type=4, cpp_type=4, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='receiver_previous_valid_sequence_number_msb', full_name='asterales.storage.ExchangeRecord.receiver_previous_valid_sequence_number_msb', index=7,
      number=8, type=4, cpp_type=4, label=1,
      has_default_value=False, default_value=0,
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
  ],
  serialized_start=199,
  serialized_end=500,
)

_EXCHANGERECORD.fields_by_name['currency'].enum_type = _CURRENCY
DESCRIPTOR.message_types_by_name['CommunityServer'] = _COMMUNITYSERVER
DESCRIPTOR.message_types_by_name['User'] = _USER
DESCRIPTOR.message_types_by_name['ExchangeRecord'] = _EXCHANGERECORD
DESCRIPTOR.enum_types_by_name['Currency'] = _CURRENCY
_sym_db.RegisterFileDescriptor(DESCRIPTOR)

CommunityServer = _reflection.GeneratedProtocolMessageType('CommunityServer', (_message.Message,), dict(
  DESCRIPTOR = _COMMUNITYSERVER,
  __module__ = 'storage_pb2'
  # @@protoc_insertion_point(class_scope:asterales.storage.CommunityServer)
  ))
_sym_db.RegisterMessage(CommunityServer)

User = _reflection.GeneratedProtocolMessageType('User', (_message.Message,), dict(
  DESCRIPTOR = _USER,
  __module__ = 'storage_pb2'
  # @@protoc_insertion_point(class_scope:asterales.storage.User)
  ))
_sym_db.RegisterMessage(User)

ExchangeRecord = _reflection.GeneratedProtocolMessageType('ExchangeRecord', (_message.Message,), dict(
  DESCRIPTOR = _EXCHANGERECORD,
  __module__ = 'storage_pb2'
  # @@protoc_insertion_point(class_scope:asterales.storage.ExchangeRecord)
  ))
_sym_db.RegisterMessage(ExchangeRecord)


# @@protoc_insertion_point(module_scope)
