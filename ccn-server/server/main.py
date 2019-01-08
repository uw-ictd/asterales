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

from dandelion_protocol.definitions import ActionTypes, make_network_address
import hashlib
import time
import requests

import cbor
from flask import Flask
from flask import request

app = Flask(__name__)

@app.route('/')
def hello_world():
    assert request.path == "/"
    return 'Hello, World!'


@app.route('/register/user', methods=['POST'])
def register_user():
    raise NotImplementedError()


@app.route('/register/network', methods=['POST'])
def register_network():
    app.logger.debug("got register network")
    app.logger.debug("Method is %s", request.method)
    app.logger.debug(request.mimetype)
    app.logger.debug(request.content_type)
    app.logger.debug(request.content_encoding)
    # Parse the outer data layer from wire format
    data = cbor.loads(request.data)
    raw_message = data['msg']
    signature = data['network_sig']

    # Parse the inner message from wire format
    message = cbor.loads(raw_message)
    key = nacl.signing.VerifyKey(message['key'], encoder=nacl.encoding.RawEncoder)
    verified = key.verify(raw_message, signature, encoder=nacl.encoding.RawEncoder)

    app.logger.info("Verified? %s", verified)
    if not verified:
        raise IndexError()

    return "Network key was verified."


@app.route('/user/<user_id>')
def existing_user(user_id):
    raise NotImplementedError()


@app.route('/status/backhaul')
def backhaul_status():
    raise NotImplementedError()


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

    def add_net(self, network_id, payload, wait=None):
        address = make_network_address(network_id)
        return self._send_transaction(ActionTypes.ADD_NET.value, payload, [address], wait=wait)

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
    logging.getLogger().setLevel(logging.DEBUG)
    signing_key, verify_key = initialize_crdt_key()
    signed_message = signing_key.sign(b'hello')
    print("signed message")
    print(signed_message)
    print(signed_message.signature)
    print(signed_message.message)
    # TODO(matt9j) Remove debug flag before deployment
    app.run(debug=True, host='0.0.0.0', port=5000)
