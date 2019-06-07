"""Convenience functions for parsing protobufs into native python objects.

This module is designed for completeness and simplicity over efficiency.
"""

import collections

import asterales_protocol.messages.handshake_pb2 as handshake_pb2
import asterales_protocol.messages.storage_pb2 as storage_pb2


UnpackedExchangeRecord = collections.namedtuple("UnpackedExchangeRecord", [
    "receiver_signature",
    "receiver_signed_blob",
    "sender_signature",
    "sender_signed_blob",
    "sender_id",
    "receiver_id",
    "receiver_sequence_number_lsb",
    "receiver_sequence_number_msb",
    "amount",
    "currency",
])


def parse_exchange_record(record_blob):
    exchange_message = handshake_pb2.Exchange()
    exchange_message.ParseFromString(record_blob)

    sender_exchange = handshake_pb2.Exchange.Partial()
    sender_exchange.ParseFromString(exchange_message.partial_exchange)

    core_exchange = handshake_pb2.Exchange.Core()
    core_exchange.ParseFromString(sender_exchange.core_exchange)

    return UnpackedExchangeRecord(
        receiver_signature=exchange_message.receiver_signature,
        receiver_signed_blob=exchange_message.partial_exchange,
        sender_signature=sender_exchange.sender_signature,
        sender_signed_blob=sender_exchange.core_exchange,
        sender_id=core_exchange.sender_id,
        receiver_id=core_exchange.receiver_id,
        receiver_sequence_number_lsb=core_exchange.receiver_sequence_number_lsb,
        receiver_sequence_number_msb=core_exchange.receiver_sequence_number_msb,
        amount=core_exchange.amount,
        currency=core_exchange.currency
    )
