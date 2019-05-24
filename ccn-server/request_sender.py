import requests

import nacl.signing
import nacl.encoding

import asterales_protocol.messages.handshake_pb2 as handshake
import asterales_protocol.messages.storage_pb2 as storage


def add_community(signing_key, verify_key):
    """Add a test community to the network"""
    new_community_info = storage.CommunityServer()
    new_community_info.id = 1
    new_community_info.verify_key = verify_key.encode(encoder=nacl.encoding.RawEncoder)
    new_community_info.display_name = "New Community One".encode('utf8')

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


#def add_user():
 #   """Add a test user to the network."""




#binary_test = test.SerializeToString()

#message_container = handshake.AddCommunity()

#newMessasge = message_container.ParseFromString(binary_test)


# Generate an exchange between the user and community.


if __name__ == "__main__":
    # Generate the key for the new community.
    community_signing_key = nacl.signing.SigningKey.generate()
    community_verify_key = community_signing_key.verify_key
    add_community(community_signing_key, community_verify_key)

    # Generate the key for the user.
    user_signing_key = nacl.signing.SigningKey.generate()
    user_verify_key = user_signing_key.verify_key

    #add_user()
