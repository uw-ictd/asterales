import cbor
import requests

import nacl.signing
import nacl.encoding

import asterales_protocol.messages.handshake_pb2 as handshake
import asterales_protocol.messages.storage_pb2 as storage


def set_server_data(entity_id, signing_key):
    """Set parameters in the running community server"""
    data = {'signing_key': signing_key.encode(encoder=nacl.encoding.RawEncoder),
            'id': entity_id,
            }
    res = requests.post(url="http://localhost:5000/debug/set_identity",
                        data=cbor.dumps(data),
                        headers={'Content-Type': 'application/octet-stream'})

    print(res)
    for line in res.iter_lines():
        print(line)


def add_community(entity_id, verify_key):
    """Add a test community to the network"""
    new_community_info = storage.Entity()
    new_community_info.id = entity_id
    new_community_info.verify_key = verify_key.encode(encoder=nacl.encoding.RawEncoder)
    new_community_info.server.display_name = "New Community One".encode('utf8')

    binary_new_community_info = new_community_info.SerializeToString()

    add_community_message = handshake.AddCommunity()
    add_community_message.anchor_id = 0
    # TODO(matt9j) Figure out how the add signature will work for the first community.
    add_community_message.anchor_signature = b''
    add_community_message.new_community = binary_new_community_info

    binary_add_community = add_community_message.SerializeToString()

    res = requests.post(url="http://localhost:5000/register/community",
                        data=binary_add_community,
                        headers={'Content-Type': 'application/octet-stream'})

    print(res)
    for line in res.iter_lines():
        print(line)


def add_user(community_signing_key, user_signing_key, user_verify_key, user_id):
    """Add a test user to the network."""

    new_user_info = storage.Entity()
    new_user_info.id = user_id
    new_user_info.verify_key = user_verify_key.encode(encoder=nacl.encoding.RawEncoder)
    new_user_info.user.display_name = "New User One".encode('utf8')
    new_user_info.user.home_community_id = 1

    new_user_blob = new_user_info.SerializeToString()
    signature = community_signing_key.sign(new_user_blob).signature

    add_user_message = handshake.AddUser()
    add_user_message.new_user = new_user_blob
    add_user_message.home_signature = signature

    binary_add_user = add_user_message.SerializeToString()
    res = requests.post(url="http://localhost:5000/register/user",
                        data=binary_add_user,
                        headers={'Content-Type': 'application/octet-stream'})

    print(res)
    for line in res.iter_lines():
        print(line)


# Generate an exchange between the user and community.
def transfer_community_to_user(user_id, user_crdt_sqn, previous_sqn, amount, user_signing_key,
                               community_verify_key, upload_uri):
    """Transfer funds from the community to the user.

    Since the user is receiving, the user is responsible for ensuring the
    upload succeeds and picking a valid crdt sqn.
    """
    if user_crdt_sqn < 0:
        raise ValueError("the sequence number must be positive")

    sequence_lsb = user_crdt_sqn & 0xFFFFFFFFFFFFFFFF
    sequence_msb = user_crdt_sqn >> 64

    send_request = {"receiver_id": user_id,
                    "sequence_lsb": sequence_lsb,
                    "sequence_msb": sequence_msb,
                    "amount": amount
                    }

    serialized_send_request = cbor.dumps(send_request)
    initiate_response = requests.post(
        url="http://localhost:5000/exchange/initiateSend",
        data=serialized_send_request,
        headers={'Content-Type': 'application/octet-stream'})

    if not initiate_response.ok:
        print(initiate_response)
        for line in initiate_response.iter_lines():
            print(line)
        raise RuntimeError("the transfer was rejected by the community server")

    partial_exchange_blob = initiate_response.content

    partial_exchange = handshake.Exchange.Partial()
    partial_exchange.ParseFromString(partial_exchange_blob)

    previous_lsb = previous_sqn & 0xFFFFFFFFFFFFFFFF
    previous_msb = previous_sqn >> 64
    partial_exchange.receiver_previous_valid_sequence_number_lsb = previous_lsb
    partial_exchange.receiver_previous_valid_sequence_number_msb = previous_msb

    # TODO(matt9j) Validate and lookup the community key.
    #community_verify_key.verify(partial_exchange.core_exchange,
    #                            partial_exchange.sender_signature)
    # TODO(matt9j) Validate core blob actually matches what we wanted to do.
    full_exchange = handshake.Exchange()
    full_exchange.partial_exchange = partial_exchange_blob
    full_exchange.receiver_signature = user_signing_key.sign(
        partial_exchange_blob,
        encoder=nacl.encoding.RawEncoder).signature

    full_exchange_blob = full_exchange.SerializeToString()

    upload_response = requests.post(
        url=upload_uri,
        data=full_exchange_blob,
        headers={'Content-Type': 'application/octet-stream'})

    print(upload_response)
    for line in upload_response.iter_lines():
        print(line)


# Ask for a garbage collect.
def garbage_collect(user_id, crdt_sqn, host):
    """Garbage collect outstanding records from a user
    """
    if crdt_sqn < 0:
        raise ValueError("the sequence number must be positive")

    flatten_request = {"origin": host,
                       "sqn": crdt_sqn,
                       "entity_id": user_id,
                       }

    serialized_flatten_request = cbor.dumps(flatten_request)
    response = requests.post(
        url="http://localhost:5000/crdt/flattenDeltaCrdt",
        data=serialized_flatten_request,
        headers={'Content-Type': 'application/octet-stream'})

    if not response.ok:
        print(response)
        for line in response.iter_lines():
            print(line)
        raise RuntimeError("the flatten was rejected by the community server")


if __name__ == "__main__":
    # Generate the key for the new community.
    community_signing_key = nacl.signing.SigningKey.generate()
    community_verify_key = community_signing_key.verify_key
    set_server_data(1, community_signing_key)
    add_community(1, community_verify_key)

    # Generate the key for the user.
    user_signing_key = nacl.signing.SigningKey.generate()
    user_verify_key = user_signing_key.verify_key
    user_id = 2

    add_user(community_signing_key, user_signing_key, user_verify_key, user_id)

    '''
    transfer_community_to_user(user_id=user_id,
                               user_crdt_sqn=1337,
                               amount=42,
                               user_signing_key=user_signing_key,
                               community_verify_key=community_verify_key,
                               upload_uri="http://localhost:5000/exchange/ledgerCrdtUpload")
                               '''

    transfer_community_to_user(user_id=user_id,
                               user_crdt_sqn=1337,
                               previous_sqn=0,
                               amount=42,
                               user_signing_key=user_signing_key,
                               community_verify_key=community_verify_key,
                               upload_uri="http://localhost:5000/exchange/deltaCrdtUpload")
    transfer_community_to_user(user_id=user_id,
                               user_crdt_sqn=1338,
                               previous_sqn=1337,
                               amount=42,
                               user_signing_key=user_signing_key,
                               community_verify_key=community_verify_key,
                               upload_uri="http://localhost:5000/exchange/deltaCrdtUpload")
    transfer_community_to_user(user_id=user_id,
                               user_crdt_sqn=1339,
                               previous_sqn=1338,
                               amount=42,
                               user_signing_key=user_signing_key,
                               community_verify_key=community_verify_key,
                               upload_uri="http://localhost:5000/exchange/deltaCrdtUpload")

    garbage_collect(user_id, 1338, "felix")


