"""A module containing the implementation of an optimized delta propagating CRDT
"""

import asterales_protocol.parse_helpers as asterales_parsers


class Element(object):
    def __init__(self, record):
        self.sources = {}
        self.record_blob = record

    def add_source(self, source):
        self.sources.add(source)


class DeltaPropCrdt(object):
    def __init__(self, neighbors):
        self.delta_set = set()
        self.local_state = {}
        self.neighbors = neighbors

    def insert_exchange(self, source, record_blob):
        exchange = asterales_parsers.parse_exchange_record(record_blob)
        receiver_id = exchange.receiver_id
        sequence_number = (exchange.receiver_sequence_number_msb * (2**64)
                           + exchange.receiver_sequence_number_lsb)

        inflates_state = False
        if exchange.receiver_id not in self.local_state:
            inflates_state = True
            self.local_state[receiver_id] = {}

        if sequence_number not in self.local_state[receiver_id]:
            inflates_state = True
            self.local_state[receiver_id][sequence_number] = Element(record_blob)

        self.local_state[receiver_id][sequence_number].add_source(source)

        if inflates_state:
            self.delta_set.add(self.local_state[receiver_id][sequence_number])

    def propagate_delta(self):
        # TODO(matt9j) This implementation maybe could be faster, or at least
        #  amortized!
        neighbor_packages = {}
        for neighbor in self.neighbors:
            neighbor_packages[neighbor] = {}

        # Sort the deltas into queues for neighbors that should get them
        while self.delta_set:
            delta = self.delta_set.pop()
            neighbors_to_send = self.neighbors - delta.sources
            for neighbor in neighbors_to_send:
                neighbor_packages[neighbor].add(delta)

        for neighbor, package in neighbor_packages.items():
            if len(package) != 0:
                send_neighbor_package(neighbor, package)


def send_neighbor_package(neighbor, neighbor_package):
    print("Sending")
    raise NotImplementedError()


