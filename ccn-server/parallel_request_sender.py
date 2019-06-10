import argparse
import multiprocessing
import nacl.signing
import timeit

import request_sender as sender


def _parse_args():
    parser = argparse.ArgumentParser()

    parser.add_argument("--users", help="The number of users", type=int)
    parser.add_argument("--messages_per_user",
                        help="The number of transactions per user",
                        type=int)

    args = parser.parse_args()

    return args


class FakeCommunity(object):
    def __init__(self, entity_id):
        self.signing_key = nacl.signing.SigningKey.generate()
        self.verify_key = self.signing_key.verify_key
        self.id = entity_id


class FakeUser(object):
    def __init__(self, entity_id):
        self.signing_key = nacl.signing.SigningKey.generate()
        self.verify_key = self.signing_key.verify_key
        self.id = entity_id
        self.sqn = 0


class ParallelRequester(object):
    def __init__(self, server_url, user_count, message_count, max_parallel):
        self.server_url = server_url
        self.user_count = user_count
        self.messages_per_user = message_count
        self.community = FakeCommunity(1)
        self.users = [FakeUser(x) for x in range(2, user_count + 2)]

    def register_entities(self):
        # Register the community and sync the keys with the server.
        sender.set_server_data(self.community.id, self.community.signing_key)
        sender.add_community(self.community.id, self.community.verify_key)

        # Register the users belonging to the community.
        for user in self.users:
            sender.add_user(self.community.signing_key, self.community.id,
                            user.signing_key, user.verify_key, user.id)

    def generate_requests(self):
        # Do sequentially for now
        for message_i in range(self.messages_per_user):
            for user in self.users:
                sender.transfer_community_to_user(
                    user_id=user.id,
                    previous_sqn=user.sqn,
                    user_crdt_sqn=(user.sqn + 1),
                    amount=42,
                    user_signing_key=user.signing_key,
                    community_verify_key=self.community.verify_key,
                    upload_uri="http://localhost:5000/exchange/ledgerCrdtUpload")
                user.sqn += 1


if __name__ == "__main__":
    options = _parse_args()
    requester = ParallelRequester("http://localhost:5000",
                                  options.users,
                                  options.messages_per_user,
                                  1)

    requester.register_entities()
    print("debug info")
    print(requester.users[0].id)
    print(requester.users[0].signing_key)
    print(requester.users[0].verify_key)
    print("About to time---------------")
    print(timeit.Timer(requester.generate_requests).timeit(1))
