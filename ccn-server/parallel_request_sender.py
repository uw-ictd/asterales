import argparse
import multiprocessing
import nacl.signing
import requests
import timeit

from functools import partial

import request_sender as sender


def _parse_args():
    parser = argparse.ArgumentParser()

    parser.add_argument("--users", help="The number of users", type=int)
    parser.add_argument("--messages_per_user",
                        help="The number of transactions per user",
                        type=int)
    parser.add_argument("-j", "--parallelism",
                        help="The number of parallel requesting processes",
                        type=int)
    parser.add_argument("--delta", help="Use delta crdt", action="store_true")

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


def _send_exchange_messages(messages_per_user, community_verify_key, uri, mapped_user):
    session = requests.session()
    for message_i in range(messages_per_user):
        sender.transfer_community_to_user(
            user_id=mapped_user.id,
            previous_sqn=mapped_user.sqn,
            user_crdt_sqn=(mapped_user.sqn + 1),
            amount=42,
            user_signing_key=mapped_user.signing_key,
            community_verify_key=community_verify_key,
            upload_uri=uri,
            http_session=session)
        mapped_user.sqn += 1
    return mapped_user


def _send_garbage_collects(max_sqn, user):
    sender.garbage_collect(user.id, max_sqn)


class ParallelRequester(object):
    def __init__(self, server_url, user_count, message_count, max_parallel):
        self.server_url = server_url
        self.user_count = user_count
        self.messages_per_user = message_count
        self.community = FakeCommunity(1)
        self.users = [FakeUser(x) for x in range(2, user_count + 2)]
        self.pool = multiprocessing.Pool(processes=max_parallel)

    def register_entities(self):
        # Register the community and sync the keys with the server.
        sender.set_server_data(self.community.id, self.community.signing_key)
        sender.add_community(self.community.id, self.community.verify_key)

        # Register the users belonging to the community.
        for user in self.users:
            sender.add_user(self.community.signing_key, self.community.id,
                            user.signing_key, user.verify_key, user.id)

    def generate_ledger_requests(self):
        bound_sender = partial(_send_exchange_messages,
                               self.messages_per_user,
                               self.community.verify_key,
                               "http://localhost:5000/exchange/ledgerCrdtUpload")
        # Map into the worker pool for parallel execution.
        self.pool.map(bound_sender, self.users)

    def generate_delta_requests(self):
        general_session = requests.session()
        bound_sender = partial(_send_exchange_messages,
                               self.messages_per_user,
                               self.community.verify_key,
                               "http://localhost:5000/exchange/deltaCrdtUpload")
        # Map into the worker pool for parallel execution.
        self.pool.map(bound_sender, self.users)
        # Push a an update to ensure sync
        sender.force_delta_propagation(general_session)
        # Garbage collect in parallel per user
        bound_collector = partial(_send_garbage_collects,
                                  self.messages_per_user)
        self.pool.map(bound_collector, self.users)


if __name__ == "__main__":
    options = _parse_args()
    requester = ParallelRequester("http://localhost:5000",
                                  options.users,
                                  options.messages_per_user,
                                  options.parallelism)

    requester.register_entities()
    print("------------------------------------------")
    print("Beginning a run with the following options")
    print(options)
    if options.delta:
        print(timeit.Timer(requester.generate_delta_requests).timeit(1))
    else:
        print(timeit.Timer(requester.generate_ledger_requests).timeit(1))

    # Print a blank line for spacing
    print("")
