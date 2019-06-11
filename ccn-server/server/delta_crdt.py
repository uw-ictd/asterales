"""A module containing the implementation of an optimized delta propagating CRDT
"""

import cbor2
import logging
import lzma
import requests
import threading

import asterales_protocol.parse_helpers as asterales_parsers


class Element(object):
    def __init__(self, record, sender, previous_sqn):
        self.sources = set()
        self.sender = sender
        self.previous_sqn = previous_sqn
        self.record_blob = record

    def add_source(self, source):
        self.sources.add(source)


class DeltaPropCrdt(object):
    def __init__(self, host, neighbors, max_pending_delta_count,
                 delta_timeout_seconds):
        self.delta_set = set()
        self.local_state = {}
        self.neighbors = set(neighbors)
        self.host = host
        self.max_delta_count = max_pending_delta_count
        self.delta_timeout_seconds = delta_timeout_seconds
        self.propagate_timer = None
        self.propagate_lock = threading.Lock()
        self.logger = logging.getLogger(__name__)
        self.logger.setLevel(logging.INFO)

    def insert_exchange(self, source, record_blob):
        exchange = asterales_parsers.parse_exchange_record(record_blob)
        receiver_id = exchange.receiver_id
        sequence_number = (exchange.receiver_sequence_number_msb * (2**64)
                           + exchange.receiver_sequence_number_lsb)
        last_valid_receive_sqn = exchange.last_valid_sequence_number_msb * (2**64) + \
                                 exchange.last_valid_sequence_number_lsb

        self.logger.debug("inserting exchange (%d, %d] for %d",
                          last_valid_receive_sqn, sequence_number, receiver_id)

        inflates_state = False
        if exchange.receiver_id not in self.local_state:
            inflates_state = True
            self.local_state[receiver_id] = {}

        if sequence_number not in self.local_state[receiver_id]:
            inflates_state = True
            self.local_state[receiver_id][sequence_number] = \
                Element(record_blob, exchange.sender_id, last_valid_receive_sqn)

        self.local_state[receiver_id][sequence_number].add_source(source)

        if inflates_state:
            self.logger.debug("state inflated by rxid:%d, sqn:%d",
                              receiver_id, sequence_number)

            self.delta_set.add(self.local_state[receiver_id][sequence_number])

            # Send out our queued deltas once we start to get too many.
            # TODO(matt9j) Make more dynamic based on available system
            #  resources for better scaling.
            if len(self.delta_set) >= self.max_delta_count:
                self.propagate_delta()
            elif self.propagate_timer is None:
                self.propagate_timer = threading.Timer(self.delta_timeout_seconds,
                                                       self.propagate_delta)
                self.propagate_timer.start()
                self.logger.debug("scheduled propagate_timer: %s",
                                  self.propagate_timer)

    def propagate_delta(self):
        self.logger.debug("Attempting to propagate delta now")
        if not self.propagate_lock.acquire(blocking=False):
            # If someone else is propagating then don't worry about servicing
            # this call to propagate too. As long as someone does the work
            # it's okay : )
            self.logger.debug("Failed to acquire propagate lock")
            return

        try:
            self.logger.info("Propagating deltas now")
            # Cancel any outstanding propagate timers
            if self.propagate_timer is not None:
                self.propagate_timer.cancel()
                self.propagate_timer = None

            self.logger.debug("beginning to build propagation sets")
            # TODO(matt9j) This implementation maybe could be faster, or at
            #  least amortized!
            neighbor_packages = {}
            for neighbor in self.neighbors:
                neighbor_packages[neighbor] = set()

            # Sort the deltas into queues for neighbors that should get them
            while self.delta_set:
                delta = self.delta_set.pop()
                neighbors_to_send = self.neighbors - delta.sources
                for neighbor in neighbors_to_send:
                    self.logger.debug("sending delta to neighbor: %s",
                                      neighbor)
                    # TODO(matt9j) Think about if this actually needs to send
                    #  the list of all the sources along to the next node.
                    neighbor_packages[neighbor].add(delta.record_blob)

            for neighbor, package in neighbor_packages.items():
                if len(package) != 0:
                    self.send_neighbor_package(neighbor, package)
        except Exception as e:
            self.logger.exception(e)
        finally:
            self.propagate_lock.release()

    def get_impacted_senders(self, receiver_id):
        self.logger.debug("Getting impacted senders for %d", receiver_id)
        senders = set()
        for sqn, element in self.local_state[receiver_id].items():
            senders.add(element.sender)
        return senders

    def get_endorsing_records(self, receiver_id, current_frontier,
                              proposed_frontier):
        self.logger.info("getting endorsing records (%d, %d] for %d",
                         current_frontier, proposed_frontier, receiver_id)

        # Prune local state as needed.
        keys_to_drop = []
        for sqn in self.local_state[receiver_id].keys():
            if sqn <= current_frontier:
                keys_to_drop.append(sqn)
        for key in keys_to_drop:
            self.logger.debug("dropping gc'd record receiver: %d, sqn: %d",
                              receiver_id,
                              key)
            del self.local_state[receiver_id][key]

        available_sqns = list(self.local_state[receiver_id].keys())
        available_sqns.sort()
        self.logger.debug("Available sqns for id %d : %s",
                          receiver_id,
                          available_sqns)

        endorsing_records = []
        frontier = current_frontier
        for sqn in available_sqns:
            element = self.local_state[receiver_id][sqn]
            self.logger.debug("examining element at sqn: %d", sqn)
            if element.previous_sqn != frontier:
                self.logger.info("Unable to satisfy endorsement request previous: %d frontier: %d",
                                 element.previous_sqn, frontier)
                return None
            frontier = sqn
            endorsing_records.append(element.record_blob)
            if frontier >= proposed_frontier:
                break

        return endorsing_records

    def garbage_collect(self):
        # identify runs
        # for each run, upload to ledger the maximum sqn of the run
        # on commit validator will reach out to confirm,
        # and we can delete run from local storage
        raise NotImplementedError()

    def process_neighbor_package(self, compressed_blob):
        # Unzip
        uncompressed_blob = lzma.decompress(compressed_blob)
        payload = cbor2.loads(uncompressed_blob)

        source = payload["source"]
        package = payload["pkg"]

        for delta_blob in package:
            self.insert_exchange(source, delta_blob)

    def send_neighbor_package(self, neighbor, neighbor_package):
        self.logger.info("sending deltas to neighbor %s", neighbor)

        payload = {"source": self.host,
                   "pkg": neighbor_package,
                   }

        serialized_package = cbor2.dumps(payload)
        compressed_package = lzma.compress(serialized_package)

        res = requests.post(url="http://" + neighbor + "/crdt/neighborPackage",
                            data=compressed_package,
                            headers={'Content-Type': 'application/octet-stream'})

        if not res.ok:
            self.logger.error("failed to send to neighbor %s. Response: %s",
                              neighbor, res)
