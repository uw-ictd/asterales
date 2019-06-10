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
    ENTITY = '0000'
    CRDT = '0001'


class ActionTypes(enum.Enum):
    """The types of messages available for processing"""
    ADD_USER = 0
    ADD_NET = 1
    ADD_LEDGER_CRDT = 2
    FLATTEN_DELTA_CRDT = 3


def make_crdt_address(entity_id):
    id_string = '{:X}'.format(entity_id)

    if len(id_string) > _CHAIN_STRUCTURE_ADDRESS_MAX_LENGTH:
        raise ValueError('The CRDTId must be at most {} hex characters \'{}\' is {} characters'.format(
        _CHAIN_STRUCTURE_ADDRESS_MAX_LENGTH, id_string, len(id_string)))

    # Pad the user id out to the max length
    padded_id = id_string.rjust(_CHAIN_STRUCTURE_ADDRESS_MAX_LENGTH, '0')

    return FAMILY_METADATA['prefixes'][0] + ChainStructureTag.CRDT.value + padded_id

def make_entity_address(entity_id):
    # TODO(matt9j) Clean up user id handling and separate from IMSI
    id_string = '{:X}'.format(entity_id)

    if len(id_string) > _CHAIN_STRUCTURE_ADDRESS_MAX_LENGTH:
        raise ValueError('The entityBalanceId must be at most {} hex characters \'{}\' is {} characters'.format(
            _CHAIN_STRUCTURE_ADDRESS_MAX_LENGTH, id_string, len(id_string)))

    # Pad the user id out to the max length
    padded_id = id_string.rjust(_CHAIN_STRUCTURE_ADDRESS_MAX_LENGTH, '0')

    return FAMILY_METADATA['prefixes'][0] + ChainStructureTag.ENTITY.value + padded_id
