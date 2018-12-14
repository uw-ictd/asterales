# Copyright 2017 Intel Corporation
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

import base64
import cbor
import enum
import hashlib
import requests
import time
import yaml

from sawtooth_signing import create_context
from sawtooth_signing import CryptoFactory
from sawtooth_signing import ParseError
from sawtooth_signing.secp256k1 import Secp256k1PrivateKey

from sawtooth_sdk.protobuf.transaction_pb2 import TransactionHeader
from sawtooth_sdk.protobuf.transaction_pb2 import Transaction
from sawtooth_sdk.protobuf.batch_pb2 import BatchList
from sawtooth_sdk.protobuf.batch_pb2 import BatchHeader
from sawtooth_sdk.protobuf.batch_pb2 import Batch

from client_cli.exceptions import CrdtClientException


FAMILY_METADATA = {
    'name': 'billing-crdt',
    'versions': ['0.0.1'],
    }

FAMILY_METADATA['prefixes'] = [
    hashlib.sha512(FAMILY_METADATA['name'].encode('utf-8')).hexdigest()[0:6],
    ]

_CHAIN_STRUCTURE_ADDRESS_MAX_LENGTH = 60


class ChainStructureTag(enum.Enum):
    """Tags following the transaction family prefix for different chain structures"""
    USERS = '0000'
    NETWORKS = '0001'
    CRDT = '0002'


class ActionTypes(enum.Enum):
    """The types of messages available for processing"""
    ADD_USER = 0
    ADD_NET = 1
    SPEND = 2
    TOP_UP = 3


def make_crdt_address(name):
    return FAMILY_METADATA['prefixes'][0] + hashlib.sha512(
        name.encode('utf-8')).hexdigest()[-64:]


def make_user_address(user_id):
    # TODO(matt9j) Clean up user id handling and separate from IMSI
    # Check if the user_id is a valid hex string
    try:
        int(user_id, 16)
    except ValueError:
        raise ValueError('The UserId \'{}\' is not a valid hex string'.format(user_id))

    if len(user_id) > _CHAIN_STRUCTURE_ADDRESS_MAX_LENGTH:
        raise ValueError('The UserId must be at most {} hex characters \'{}\' is {} characters'.format(
                _CHAIN_STRUCTURE_ADDRESS_MAX_LENGTH, user_id, len(user_id)))
    # Pad the user id out to the max length
    padded_id = user_id.rjust(_CHAIN_STRUCTURE_ADDRESS_MAX_LENGTH, '0')

    return FAMILY_METADATA['prefixes'][0] + ChainStructureTag.USERS.value + padded_id


def _sha512(data):
    return hashlib.sha512(data).hexdigest()


class Client:
    def __init__(self, url, keyfile=None):
        self.url = url

        if keyfile is not None:
            try:
                with open(keyfile) as fd:
                    private_key_str = fd.read().strip()
                    fd.close()
            except OSError as err:
                raise CrdtClientException(
                    'Failed to read private key: {}'.format(str(err)))

            try:
                private_key = Secp256k1PrivateKey.from_hex(private_key_str)
            except ParseError as e:
                raise CrdtClientException(
                    'Unable to load private key: {}'.format(str(e)))

            self._signer = CryptoFactory(
                create_context('secp256k1')).new_signer(private_key)

    def add_user(self, imsi, public_key, home_network, wait=None):
        action = ActionTypes.ADD_USER.value
        action_payload = cbor.dumps({'imsi': imsi, 'pub_key': public_key, 'home_net': home_network})
        address = make_user_address(imsi)
        return self._send_transaction(action, action_payload, [address], wait=wait)

    def list(self):
        result = self._send_request(
            "state?address={}".format(
                self._get_prefix()))

        try:
            encoded_entries = yaml.safe_load(result)["data"]

            return [
                cbor.loads(base64.b64decode(entry["data"]))
                for entry in encoded_entries
            ]

        except BaseException:
            return None

    def show_user(self, imsi):
        address = make_user_address(imsi)

        result = self._send_request("state/{}".format(address), name=imsi,)

        try:
            print("Got to the load data part!")
            return cbor.loads(
                base64.b64decode(
                    yaml.safe_load(result)["data"]))

        except BaseException:
            return None

    def _get_status(self, batch_id, wait):
        try:
            result = self._send_request(
                'batch_statuses?id={}&wait={}'.format(batch_id, wait),)
            return yaml.safe_load(result)['data'][0]['status']
        except BaseException as err:
            raise CrdtClientException(err)

    @staticmethod
    def _get_prefix():
        return _sha512('billing-crdt'.encode('utf-8'))[0:6]

    def _get_address(self, name):
        prefix = self._get_prefix()
        game_address = _sha512(name.encode('utf-8'))[64:]
        return prefix + game_address

    def _send_request(self, suffix, data=None, content_type=None, name=None):
        if self.url.startswith("http://"):
            url = "{}/{}".format(self.url, suffix)
        else:
            url = "http://{}/{}".format(self.url, suffix)

        headers = {}

        if content_type is not None:
            headers['Content-Type'] = content_type

        try:
            if data is not None:
                result = requests.post(url, headers=headers, data=data)
            else:
                result = requests.get(url, headers=headers)

            if result.status_code == 404:
                raise CrdtClientException("No such key: {}".format(name))

            elif not result.ok:
                raise CrdtClientException("Error {}: {}".format(
                    result.status_code, result.reason))

        except requests.ConnectionError as err:
            raise CrdtClientException(
                'Failed to connect to REST API: {}'.format(err))

        except BaseException as err:
            raise CrdtClientException(err)

        return result.text

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
            payload_sha512=_sha512(payload),
            batcher_public_key=self._signer.get_public_key().as_hex(),
            nonce=time.time().hex().encode()
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
