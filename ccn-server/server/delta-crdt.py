"""A module containing the implementation of an optimized delta propagating CRDT
"""

import cbor
import lzma
import requests

import asterales_protocol.parse_helpers as asterales_parsers


class Element(object):
    def __init__(self, record):
        self.sources = {}
        self.record_blob = record

    def add_source(self, source):
        self.sources.add(source)


class DeltaPropCrdt(object):
    def __init__(self, host, neighbors):
        self.delta_set = set()
        self.local_state = {}
        self.neighbors = neighbors
        self.host = host

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
                # TODO(matt9j) Think about if this actually needs to send the
                #  list of all the sources along to the next node.
                neighbor_packages[neighbor].add(delta.record_blob)

        for neighbor, package in neighbor_packages.items():
            if len(package) != 0:
                self.send_neighbor_package(neighbor, package)

    def garbage_collect(self):
        raise NotImplementedError()

    def process_neighbor_package(self, compressed_blob):
        # Unzip
        uncompressed_blob = lzma.decompress(compressed_blob)
        payload = cbor.loads(uncompressed_blob)

        source = payload["source"]
        package = payload["pkg"]

        for delta_blob in package:
            self.insert_exchange(source, delta_blob)

    def send_neighbor_package(self, neighbor, neighbor_package):
        payload = {"source": self.host,
                   "pkg": neighbor_package,
                   }

        serialized_package = cbor.dumps(payload)
        compressed_package = lzma.compress(serialized_package)

        res = requests.post(url="http://" + neighbor + ":5000/crdt/neighborPackage",
                            data=compressed_package,
                            headers={'Content-Type': 'application/octet-stream'})

        if not res.ok:
            print(res)
