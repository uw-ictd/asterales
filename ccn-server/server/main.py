import argparse

import logging
import nacl.encoding
import nacl.signing

from sawtooth_signing import create_context
from sawtooth_signing import CryptoFactory
from sawtooth_signing.secp256k1 import Secp256k1PrivateKey

from sawtooth_sdk.protobuf.transaction_pb2 import TransactionHeader
from sawtooth_sdk.protobuf.transaction_pb2 import Transaction
from sawtooth_sdk.protobuf.batch_pb2 import BatchList
from sawtooth_sdk.protobuf.batch_pb2 import BatchHeader
from sawtooth_sdk.protobuf.batch_pb2 import Batch

import asterales_protocol.parse_helpers as asterales_parsers
from asterales_protocol.definitions import ActionTypes, make_crdt_address, make_entity_address
import asterales_protocol.messages.storage_pb2 as storage_pb2
import asterales_protocol.messages.handshake_pb2 as handshake_pb2
import hashlib
import time
import requests

import cbor
from flask import Flask
from flask import request

import server.delta_crdt as crdt

app = Flask(__name__)


@app.route('/debug/set_identity', methods=['POST'])
def debug_set_identity():
    app.logger.warning("Overriding key information with external keys")
    global SIGNING_KEY
    global VERIFY_KEY
    global ENTITY_ID

    identity_data = cbor.loads(request.data)
    SIGNING_KEY = nacl.signing.SigningKey(identity_data['signing_key'],
                                          encoder=nacl.encoding.RawEncoder)
    VERIFY_KEY = SIGNING_KEY.verify_key
    ENTITY_ID = identity_data['id']

    key_data = SIGNING_KEY.encode(encoder=nacl.encoding.RawEncoder)
    with open("crdt_network_key.priv", "w+b") as f:
        f.write(key_data)

    return ''


@app.route('/register/user', methods=['POST'])
def register_user():
    app.logger.debug("got register network")
    new_user_blob = request.data
    user_id = _parse_user_id_from_add_user(new_user_blob)
    result = client.add_user(user_id, request.data)
    return result


@app.route('/register/community', methods=['POST'])
def register_network():
    app.logger.debug("got register network")
    app.logger.debug("Method is %s", request.method)
    app.logger.debug(request.mimetype)
    app.logger.debug(request.content_type)
    app.logger.debug(request.content_encoding)
    # Parse the outer data layer from wire format
    new_community_data = request.data
    community_id = _parse_id_from_add_community(new_community_data)

    # TODO(matt9j) Queue transactions when offline

    # Format and submit the ledger transaction.
    result = client.add_community(community_id, request.data)

    return result


@app.route('/user/<user_id>')
def existing_user(user_id):
    raise NotImplementedError()


@app.route('/status/backhaul')
def backhaul_status():
    raise NotImplementedError()


# Endorse an exchange where the community server sends funds to the receiver.
@app.route('/exchange/initiateSend', methods=['POST'])
def initiate_send():
    # TODO(matt9j) do a more safe deserialization.
    receiver_data = cbor.loads(request.data)

    receiver_id = receiver_data['receiver_id']
    # TODO(matt9j) Validate the sequence number is sane.
    receiver_sequence_number = (receiver_data['sequence_msb'] ** 64 +
                                receiver_data['sequence_lsb'])
    amount = receiver_data['amount']
    # TODO(matt9j) support multiple currencies.

    exchange_core_proto = handshake_pb2.Exchange.Core()
    # TODO(matt9j) UI Validation that we actually want to send!
    exchange_core_proto.sender_id = ENTITY_ID
    exchange_core_proto.receiver_id = receiver_id
    exchange_core_proto.receiver_sequence_number_lsb = receiver_data['sequence_lsb']
    exchange_core_proto.receiver_sequence_number_msb = receiver_data['sequence_msb']
    exchange_core_proto.amount = amount

    exchange_core_blob = exchange_core_proto.SerializeToString()

    partial_exchange = handshake_pb2.Exchange.Partial()
    # TODO(matt9j) Inject the signing key dependency for testing.
    partial_exchange.sender_signature = \
        SIGNING_KEY.sign(exchange_core_blob,
                         encoder=nacl.encoding.RawEncoder).signature
    partial_exchange.core_exchange = exchange_core_blob

    partial_exchange_blob = partial_exchange.SerializeToString()

    return partial_exchange_blob


@app.route('/exchange/ledgerCrdtUpload', methods=['POST'])
def ledger_crdt_upload():
    exchange = asterales_parsers.parse_exchange_record(request.data)
    result = client.add_crdt_record(exchange.receiver_id,
                                    exchange.sender_id,
                                    request.data)
    return result


@app.route('/exchange/deltaCrdtUpload', methods=['POST'])
def delta_crdt_upload():
    CRDT_INSTANCE.insert_exchange(HOSTNAME, request.data)
    return 'Upload Successful'


@app.route('/crdt/neighborPackage', methods=['POST'])
def receive_neighbor_package():
    CRDT_INSTANCE.process_neighbor_package(request.data)
    return ''


def initialize_crdt_key():
    try:
        with open("crdt_network_key.priv", "rb") as f:
            logging.debug("loading signing key from file")
            key_data = f.read()
            signing_key = nacl.signing.SigningKey(key_data, encoder=nacl.encoding.RawEncoder)
    except FileNotFoundError:
        logging.warning("no key file present, generating new network signing key")
        signing_key = nacl.signing.SigningKey.generate()
        key_data = signing_key.encode(encoder=nacl.encoding.RawEncoder)
        with open("crdt_network_key.priv", "w+b") as f:
            f.write(key_data)

    return signing_key, signing_key.verify_key


def _parse_id_from_add_community(action_payload):
    # Parse outer message
    add_community_payload = handshake_pb2.AddCommunity()
    add_community_payload.ParseFromString(action_payload)

    new_community_info = storage_pb2.Entity()
    new_community_info.ParseFromString(add_community_payload.new_community)

    community_id = new_community_info.id

    return community_id


def _parse_user_id_from_add_user(add_user_blob):
    add_user_payload = handshake_pb2.AddUser()
    add_user_payload.ParseFromString(add_user_blob)

    new_user_info = storage_pb2.Entity()
    new_user_info.ParseFromString(add_user_payload.new_user)

    return new_user_info.id


class CrdtClientException(Exception):
    pass


class SawtoothClient(object):
    def __init__(self, url, keyfile=None):
        self.base_url = url

        if keyfile is not None:
            with open(keyfile) as fd:
                private_key_str = fd.read().strip()
                fd.close()

            sawtooth_signing_key = Secp256k1PrivateKey.from_hex(private_key_str)

            self._signer = CryptoFactory(
                create_context('secp256k1')).new_signer(sawtooth_signing_key)

    def add_crdt_record(self, receive_entity, send_entity,
                        crdt_record, wait=None):
        crdt_address = make_crdt_address(receive_entity)
        receiver_address = make_entity_address(receive_entity)
        sender_address = make_entity_address(send_entity)

        return self._send_transaction(ActionTypes.ADD_LEDGER_CRDT.value,
                                      crdt_record,
                                      [crdt_address,
                                       receiver_address,
                                       sender_address,
                                       ],
                                      wait=wait)

    def add_community(self, network_id, payload, wait=None):
        address = make_entity_address(network_id)
        return self._send_transaction(ActionTypes.ADD_NET.value, payload,
                                      [address], wait=wait)

    def add_user(self, user_id, payload, wait=None):
        address = make_entity_address(user_id)
        return self._send_transaction(ActionTypes.ADD_USER.value, payload,
                                      [address], wait=wait)

    def _send_transaction(self, action, action_payload, addresses, wait=None):
        payload = cbor.dumps({
            'action': action,
            'payload': action_payload
        })

        header = TransactionHeader(
            signer_public_key=self._signer.get_public_key().as_hex(),
            family_name="billing-crdt",
            family_version="0.0.1",
            inputs=addresses,
            outputs=addresses,
            dependencies=[],
            payload_sha512=self._sha512(payload),
            batcher_public_key=self._signer.get_public_key().as_hex(),
            nonce=self._nonce()
        ).SerializeToString()

        signature = self._signer.sign(header)

        transaction = Transaction(
            header=header,
            payload=payload,
            header_signature=signature
        )

        batch_list = self._create_batch_list([transaction])
        batch_id = batch_list.batches[0].header_signature

        if wait and wait > 0:
            wait_time = 0
            start_time = time.time()
            response = self._send_request(
                "batches", batch_list.SerializeToString(),
                'application/octet-stream',
            )
            while wait_time < wait:
                status = self._get_status(
                    batch_id,
                    wait - int(wait_time),
                )
                wait_time = time.time() - start_time

                if status != 'PENDING':
                    return response

            return response

        return self._send_request(
            "batches", batch_list.SerializeToString(),
            'application/octet-stream',
        )

    def _send_request(self, suffix, data=None, content_type=None, name=None):
        url = "{}/{}".format(self.base_url, suffix)
        headers = {}
        if content_type is not None:
            headers['Content-Type'] = content_type

        try:
            if data is not None:
                result = requests.post(url, headers=headers, data=data)
            else:
                result = requests.get(url, headers=headers)

            if not result.ok:
                raise CrdtClientException("Error url={} name={} - {}: {}".format(
                    suffix, name, result.status_code, result.reason))

        except requests.ConnectionError as err:
            raise CrdtClientException(
                'Failed to connect to REST API: {}'.format(err))

        except BaseException as err:
            raise CrdtClientException(err)

        return result.text

    def _create_batch_list(self, transactions):
        transaction_signatures = [t.header_signature for t in transactions]

        header = BatchHeader(
            signer_public_key=self._signer.get_public_key().as_hex(),
            transaction_ids=transaction_signatures
        ).SerializeToString()

        signature = self._signer.sign(header)

        batch = Batch(
            header=header,
            transactions=transactions,
            header_signature=signature)
        return BatchList(batches=[batch])

    @staticmethod
    def _sha512(data):
        return hashlib.sha512(data).hexdigest()

    @staticmethod
    def _nonce():
        return time.time().hex().encode()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", required=True,
                        help="The host of the current server.")
    parser.add_argument("--neighbors", required=True,
                        help="The hostnames of this server's neighbors for CRDT propagation.")
    parser.add_argument("--sawtoothApi", required=True,
                        help="The sawtooth rest-api endpoint.")

    args = parser.parse_args()

    logging.getLogger().setLevel(logging.DEBUG)
    SIGNING_KEY, VERIFY_KEY = initialize_crdt_key()
    ENTITY_ID = 1
    HOSTNAME= args.host

    CRDT_INSTANCE = crdt.DeltaPropCrdt(args.host, args.neighbors.split(","),
                                       max_pending_delta_count=1000,
                                       delta_timeout_seconds=10.0)

    client = SawtoothClient(url=args.sawtoothApi,
                            keyfile="/root/.sawtooth/keys/root.priv")
    # TODO(matt9j) Remove debug flag before deployment
    app.run(debug=True, host='0.0.0.0', port=5000)
