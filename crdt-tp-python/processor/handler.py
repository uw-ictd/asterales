# Copyright 2016 Intel Corporation
# Copyright 2018 University of Washington
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
# ------------------------------------------------------------------------------

import logging

import cbor
import cbor2
import nacl.signing
import nacl.encoding
import nacl.exceptions
import requests

from sawtooth_sdk.processor.exceptions import InternalError
from sawtooth_sdk.processor.exceptions import InvalidTransaction
from sawtooth_sdk.processor.handler import TransactionHandler

from asterales_protocol.definitions import ActionTypes, make_crdt_address, make_entity_address
from asterales_protocol.definitions import FAMILY_METADATA
import asterales_protocol.messages.handshake_pb2 as handshake_pb2
import asterales_protocol.messages.storage_pb2 as storage_pb2
import asterales_protocol.parse_helpers as asterales_parsers


LOG = logging.getLogger(__name__)


class CrdtTransactionHandler(TransactionHandler):
    def __init__(self, crdt_endpoint):
        self._crdt_endpoint = crdt_endpoint

    @property
    def family_name(self):
        return FAMILY_METADATA['name']

    @property
    def family_versions(self):
        return FAMILY_METADATA['versions']

    @property
    def namespaces(self):
        return FAMILY_METADATA['prefixes']

    def apply(self, transaction, context):
        try:
            action, action_payload = _unpack_transaction(transaction)

            _do_action(action, action_payload, context, self._crdt_endpoint)
        # In Sawtooth (at least version 1.0.*) InternalErrors will result in
        # a retry, InvalidTransaction errors will reject the block,
        # and generic python errors will not be caught and will result in the
        # transaction processor crashing.
        except (InvalidTransaction, InternalError) as e:
            # Directly forward any sawtooth exceptions
            LOG.exception(e)
            raise InvalidTransaction("Internal Invalid Transaction") from e
        except Exception as e:
            # Catch any non-sawtooth exceptions at a high level, and declare
            # the transaction invalid. Clients may retry as needed.
            LOG.exception(e)
            raise InvalidTransaction("An unhandled transaction processing "
                                     "exception occurred") from e


def _unpack_transaction(transaction):
    action, action_payload = _decode_action(transaction)

    _validate_action(action)

    return action, action_payload


def _decode_action(transaction):
    try:
        content = cbor.loads(transaction.payload)
    except:
        raise InvalidTransaction('Invalid payload serialization')

    try:
        action_string = content['action']
        action = ActionTypes(action_string)
    except (AttributeError, ValueError):
        raise InvalidTransaction('action is required')

    try:
        action_payload = content['payload']
    except AttributeError:
        raise InvalidTransaction('action payload is required')

    return action, action_payload


def _validate_action(action):
    if action not in ActionTypes:
        raise InvalidTransaction('Action must be in' + str(ActionTypes))


def _do_action(action, action_payload, context, crdt_endpoint):
    if action == ActionTypes.ADD_USER:
        _add_user(action_payload, context)
    elif action == ActionTypes.ADD_NET:
        _add_net(action_payload, context)
    elif action == ActionTypes.ADD_LEDGER_CRDT:
        _add_ledger_crdt(action_payload, context)
    elif action == ActionTypes.FLATTEN_DELTA_CRDT:
        _flatten_delta_crdt(action_payload, context, crdt_endpoint)
    else:
        raise NotImplementedError("The action" + str(action) + " is not supported yet.")


def _flatten_delta_crdt(action_payload, context, crdt_endpoint):
    """Flattens contiguous local CRDT records into the entity state"""

    # Parse the request.
    flatten_request = cbor2.loads(action_payload)
    # TODO(matt9j) Use the origin as a fallback if deltas are missing.
    # request_origin = flatten_request['origin']
    entity_id = flatten_request['entity_id']
    proposed_frontier = flatten_request['sqn']

    # Lookup the current frontier sqn.
    entity_blob = _get_state_data(make_entity_address(entity_id), context)
    entity_pb = storage_pb2.Entity()
    entity_pb.ParseFromString(entity_blob)
    current_frontier = entity_pb.frontier_sequence_number
    LOG.debug('requesting endorsement for (%d, %d] for entity %d',
              current_frontier, proposed_frontier, entity_id)

    # ask the local CRDT for exchanges up to the new proposed frontier SQN
    crdt_request = {'receive_id': entity_id,
                    'current_frontier': current_frontier,
                    'proposed_frontier': proposed_frontier,
                    }

    response = requests.post(url=crdt_endpoint + "/crdt/endorsingRecords",
                             data=cbor2.dumps(crdt_request),
                             headers={'Content-Type': 'application/octet-stream'})
    if not response.ok:
        LOG.error("Unable to request endorsing crdt records %s", response)
        raise InvalidTransaction("Unable to request endorsement from CRDT")

    # Set aside the receiver information
    receiver_blob = _get_state_data(make_entity_address(entity_id),
                                    context)
    receiver_data = storage_pb2.Entity()
    receiver_data.ParseFromString(receiver_blob)
    receive_verify_key = nacl.signing.VerifyKey(receiver_data.verify_key,
                                                encoder=nacl.encoding.RawEncoder)

    # exchanges must be sorted already in ascending order by sequence number
    exchanges = cbor2.loads(response.content)
    frontier = current_frontier

    # TODO(matt9j) Possibly speedup by re-using exchange protobufs
    # validate all the exchanges
    for exchange_blob in exchanges:
        if frontier >= proposed_frontier:
            LOG.warning("Got too many exchange records or bad frontier req?!")
            break

        exchange = asterales_parsers.parse_exchange_record(exchange_blob)
        receive_sqn = exchange.receiver_sequence_number_msb * (2 ** 64) + \
                      exchange.receiver_sequence_number_lsb
        last_valid_receive_sqn = exchange.last_valid_sequence_number_msb * (2**64) + \
                                 exchange.last_valid_sequence_number_lsb
        # Validate signatures
        try:
            receive_verify_key.verify(exchange.receiver_signed_blob,
                                      exchange.receiver_signature,
                                      encoder=nacl.encoding.RawEncoder)
        except nacl.exceptions.BadSignatureError as e:
            LOG.error(e)
            raise InvalidTransaction('Exchange receive signature invalid sqn:{}'.format(
                receive_sqn))

        sender_blob = _get_state_data(make_entity_address(exchange.sender_id),
                                      context)
        sender_data = storage_pb2.Entity()
        sender_data.ParseFromString(sender_blob)
        sender_verify_key = nacl.signing.VerifyKey(sender_data.verify_key,
                                                   encoder=nacl.encoding.RawEncoder)
        try:
            sender_verify_key.verify(exchange.sender_signed_blob,
                                     exchange.sender_signature,
                                     encoder=nacl.encoding.RawEncoder)
        except nacl.exceptions.BadSignatureError:
            raise InvalidTransaction('Exchange send signature invalid sqn:{}'.format(
                receive_sqn))

        if last_valid_receive_sqn != frontier:
            LOG.warning("Gap discovered-- in this hacky initial implementation"
                        " state may now be corrupted.")
            raise InvalidTransaction()

        receiver_data.balance += exchange.amount

        # TODO(matt9j) Don't serialize all the send messages until done! Some
        #  may be repeated...
        sender_data.balance -= exchange.amount
        _set_state_data(make_entity_address(exchange.sender_id),
                        sender_data.SerializeToString(),
                        context)

        frontier = receive_sqn

    # Serialize the common receive buffer at the end of processing.
    # TODO(matt9j) Fix LSB/MSB precision laziness.
    frontier_sequence_number_lsb = frontier & 0xFFFFFFFFFFFFFFFF
    frontier_sequence_number_msb = frontier >> 64
    receiver_data.frontier_sequence_number = frontier_sequence_number_lsb
    _set_state_data(make_entity_address(exchange.receiver_id),
                    receiver_data.SerializeToString(),
                    context)


def _add_ledger_crdt(action_payload, context):
    """Add a crdt record to the on-chain crdt implementation."""

    exchange = asterales_parsers.parse_exchange_record(action_payload)

    # TODO(matt9j) handle gaps in the receive SQN?
    # TODO(matt9j) Validate that the sequence number has indeed progressed
    receive_sqn = exchange.receiver_sequence_number_msb * (2 ** 64) + \
                  exchange.receiver_sequence_number_lsb
    LOG.debug("Processing id: %d, sqn: %d to the ledger crdt",
             exchange.receiver_id, receive_sqn)

    # Validate the exchange signatures
    receiver_blob = _get_state_data(make_entity_address(exchange.receiver_id),
                                    context)
    receiver_data = storage_pb2.Entity()
    receiver_data.ParseFromString(receiver_blob)
    receive_verify_key = nacl.signing.VerifyKey(receiver_data.verify_key,
                                                encoder=nacl.encoding.RawEncoder)
    try:
        receive_verify_key.verify(exchange.receiver_signed_blob,
                                  exchange.receiver_signature,
                                  encoder=nacl.encoding.RawEncoder)
    except nacl.exceptions.BadSignatureError as e:
        LOG.error(e)
        raise InvalidTransaction('Exchange receive signature invalid sqn:{}'.format(
            receive_sqn))

    sender_blob = _get_state_data(make_entity_address(exchange.sender_id),
                                  context)
    sender_data = storage_pb2.Entity()
    sender_data.ParseFromString(sender_blob)
    sender_verify_key = nacl.signing.VerifyKey(sender_data.verify_key,
                                               encoder=nacl.encoding.RawEncoder)
    try:
        sender_verify_key.verify(exchange.sender_signed_blob,
                                 exchange.sender_signature,
                                 encoder=nacl.encoding.RawEncoder)
    except nacl.exceptions.BadSignatureError:
        raise InvalidTransaction('Exchange send signature invalid sqn:{}'.format(
            receive_sqn))

    crdt_address = make_crdt_address(exchange.receiver_id)
    current_crdt_blob = _get_state_data(crdt_address, context)

    if current_crdt_blob is not None:
        crdt_history = cbor.loads(current_crdt_blob)
    else:
        crdt_history = []

    if receive_sqn in crdt_history:
        LOG.info("Discarding duplicate upload sqn: %d", receive_sqn)
        return

    LOG.debug("Record is new, adding sqn: %d to the ledger crdt", receive_sqn)

    crdt_history.append(receive_sqn)
    _set_state_data(crdt_address, cbor.dumps(crdt_history), context)

    receiver_data.balance += exchange.amount
    _set_state_data(make_entity_address(exchange.receiver_id),
                    receiver_data.SerializeToString(),
                    context)

    sender_data.balance -= exchange.amount
    _set_state_data(make_entity_address(exchange.sender_id),
                    sender_data.SerializeToString(),
                    context)


def _add_user(serialized_payload, context):
    home_id, blob_sig, user_id, user_blob = _parse_add_user(serialized_payload)
    # TODO(matt9j) Validate the network signature against the known home network key!

    address = make_entity_address(user_id)
    data = _get_state_data(address, context)
    if data:
        raise InvalidTransaction('The user {} already exists'.format(user_id))

    _set_state_data(address, user_blob, context)


def _add_net(action_payload, context):
    # TODO(matt9j) Do a more safe deserialization.
    # Parse the outer data layer from wire format
    anchor_id, message_sig, community_id, new_community_blob = \
        _parse_add_community(action_payload)

    # TODO(matt9j) Validate the anchor and signature
    verified = True
    #     key = nacl.signing.VerifyKey(message['key'],
    #     encoder=nacl.encoding.RawEncoder)
    #     verified = key.verify(raw_message, signature,
    #     encoder=nacl.encoding.RawEncoder)
    if not verified:
        raise InvalidTransaction('Message failed network key validation')

    address = make_entity_address(community_id)
    data = _get_state_data(address, context)
    if data:
        raise InvalidTransaction('The community {} already exists'.format(community_id))

    _set_state_data(address, new_community_blob, context)

def _parse_add_community(action_payload):
    # Parse outer message
    add_community_payload = handshake_pb2.AddCommunity()
    add_community_payload.ParseFromString(action_payload)

    anchor_id = add_community_payload.anchor_id
    message_sig = add_community_payload.anchor_signature

    new_community_info = storage_pb2.Entity()
    new_community_info.ParseFromString(add_community_payload.new_community)

    community_id = new_community_info.id

    return anchor_id, message_sig, community_id, add_community_payload.new_community


def _parse_add_user(add_user_blob):
    """Deserialize the add user payload"""
    add_user_payload = handshake_pb2.AddUser()
    add_user_payload.ParseFromString(add_user_blob)
    blob_sig = add_user_payload.home_signature

    new_user_info = storage_pb2.Entity()
    new_user_info.ParseFromString(add_user_payload.new_user)

    home_id = new_user_info.user.home_community_id
    user_id = new_user_info.id

    return home_id, blob_sig, user_id, add_user_payload.new_user


def _get_state_data(address, context):
    state_entries = context.get_state([address])

    try:
        return state_entries[0].data
    except IndexError:
        return None


def _set_state_data(address, state_payload, context):
    addresses = context.set_state({address: state_payload})

    if not addresses:
        raise InternalError('State error')
