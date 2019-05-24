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

import enum
import hashlib

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


def make_user_address_from_int(id_int):
    user_id = '{:X}'.format(id_int)
    return make_user_address(user_id)


def make_network_address_from_hex(net_id):
    try:
        int(net_id, 16)
    except ValueError:
        raise ValueError('The NetworkId \'{}\' is not a valid hex string'.format(net_id))

    if len(net_id) > _CHAIN_STRUCTURE_ADDRESS_MAX_LENGTH:
        raise ValueError('The UserId must be at most {} hex characters \'{}\' is {} characters'.format(
                _CHAIN_STRUCTURE_ADDRESS_MAX_LENGTH, net_id, len(net_id)))
    # Pad the user id out to the max length
    padded_id = net_id.rjust(_CHAIN_STRUCTURE_ADDRESS_MAX_LENGTH, '0')

    return FAMILY_METADATA['prefixes'][0] + ChainStructureTag.NETWORKS.value + padded_id

def make_network_address_from_int(id_int):
    net_id = '{:X}'.format(id_int)
    return make_network_address_from_hex(net_id)
