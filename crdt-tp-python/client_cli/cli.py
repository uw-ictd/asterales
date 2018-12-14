# Copyright 2016, 2017 Intel Corporation
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

import argparse
import getpass
import logging
import os
import sys
import traceback
import pkg_resources

from colorlog import ColoredFormatter

#from sawtooth_intkey.client_cli.generate import add_generate_parser
#from sawtooth_intkey.client_cli.generate import do_generate
#from sawtooth_intkey.client_cli.populate import add_populate_parser
#from sawtooth_intkey.client_cli.populate import do_populate
#from sawtooth_intkey.client_cli.create_batch import add_create_batch_parser
#from sawtooth_intkey.client_cli.create_batch import do_create_batch
#from sawtooth_intkey.client_cli.load import add_load_parser
#from sawtooth_intkey.client_cli.load import do_load
#from sawtooth_intkey.client_cli.intkey_workload import add_workload_parser
#from sawtooth_intkey.client_cli.intkey_workload import do_workload

from client_cli.client import Client
from client_cli.exceptions import CrdtCliException, CrdtClientException


DISTRIBUTION_NAME = 'sawtooth-intkey'


DEFAULT_URL = 'http://127.0.0.1:8008'


def create_console_handler(verbose_level):
    clog = logging.StreamHandler()
    formatter = ColoredFormatter(
        "%(log_color)s[%(asctime)s %(levelname)-8s%(module)s]%(reset)s "
        "%(white)s%(message)s",
        datefmt="%H:%M:%S",
        reset=True,
        log_colors={
            'DEBUG': 'cyan',
            'INFO': 'green',
            'WARNING': 'yellow',
            'ERROR': 'red',
            'CRITICAL': 'red',
        })

    clog.setFormatter(formatter)

    if verbose_level == 0:
        clog.setLevel(logging.WARN)
    elif verbose_level == 1:
        clog.setLevel(logging.INFO)
    else:
        clog.setLevel(logging.DEBUG)

    return clog


def setup_loggers(verbose_level):
    logger = logging.getLogger()
    logger.setLevel(logging.DEBUG)
    logger.addHandler(create_console_handler(verbose_level))


def create_parent_parser(prog_name):
    parent_parser = argparse.ArgumentParser(prog=prog_name, add_help=False)
    parent_parser.add_argument(
        '-v', '--verbose',
        action='count',
        help='enable more verbose output')

    try:
        version = pkg_resources.get_distribution(DISTRIBUTION_NAME).version
    except pkg_resources.DistributionNotFound:
        version = 'UNKNOWN'

    parent_parser.add_argument(
        '-V', '--version',
        action='version',
        version=(DISTRIBUTION_NAME + ' (Hyperledger Sawtooth) version {}')
        .format(version),
        help='display version information')

    return parent_parser


def create_parser(prog_name):
    parent_parser = create_parent_parser(prog_name)

    parser = argparse.ArgumentParser(
        parents=[parent_parser],
        formatter_class=argparse.RawDescriptionHelpFormatter)

    subparsers = parser.add_subparsers(title='subcommands', dest='command')

    add_add_user_parser(subparsers, parent_parser)
    add_show_user_parser(subparsers, parent_parser)
    add_list_parser(subparsers, parent_parser)

    #add_generate_parser(subparsers, parent_parser)
    #add_load_parser(subparsers, parent_parser)
    #add_populate_parser(subparsers, parent_parser)
    #add_create_batch_parser(subparsers, parent_parser)
    #add_workload_parser(subparsers, parent_parser)

    return parser


def add_add_user_parser(subparsers, parent_parser):
    message = 'Sends a crdt add_user transaction to add <imsi> with <public_key> and <home_network>.'

    parser = subparsers.add_parser(
        'add_user',
        parents=[parent_parser],
        description=message,
        help='Adds a crdt user')

    parser.add_argument(
        'imsi',
        type=str,
        help='the identity of the user to add')

    parser.add_argument(
        'public_key',
        type=str,
        help='the user\'s public key')

    parser.add_argument(
        'home_network',
        type=str,
        help='the user home network')

    parser.add_argument(
        '--url',
        type=str,
        help='specify URL of REST API')

    parser.add_argument(
        '--keyfile',
        type=str,
        help="identify file containing user's private key")

    parser.add_argument(
        '--wait',
        nargs='?',
        const=sys.maxsize,
        type=int,
        help='set time, in seconds, to wait for transaction to commit')


def do_add_user(args):
    imsi, pub_key, home_net, wait = args.imsi, args.public_key, args.home_network, args.wait
    client = _get_client(args)
    response = client.add_user(imsi, pub_key, home_net, wait)
    print(response)


def add_show_user_parser(subparsers, parent_parser):
    message = 'Shows the value of the key <name>.'

    parser = subparsers.add_parser(
        'show_user',
        parents=[parent_parser],
        description=message,
        help='Displays the specified user value')

    parser.add_argument(
        'imsi',
        type=str,
        help='id of the user to show')

    parser.add_argument(
        '--url',
        type=str,
        help='specify URL of REST API')


def do_show_user(args):
    imsi = args.imsi
    client = _get_client(args)
    value = client.show_user(imsi)
    print('{}: {}'.format(imsi, value))


def add_list_parser(subparsers, parent_parser):
    message = 'Shows the values of all keys in intkey state.'

    parser = subparsers.add_parser(
        'list',
        parents=[parent_parser],
        description=message,
        help='Displays all intkey values')

    parser.add_argument(
        '--url',
        type=str,
        help='specify URL of REST API')


def do_list(args):
    client = _get_client(args)
    results = client.list()
    for pair in results:
        for name, value in pair.items():
            print('{}: {}'.format(name, value))


def _get_client(args):
    return Client(
        url=DEFAULT_URL if args.url is None else args.url,
        keyfile=_get_keyfile(args))


def _get_keyfile(args):
    try:
        if args.keyfile is not None:
            return args.keyfile
    except AttributeError:
        return None

    real_user = getpass.getuser()
    home = os.path.expanduser("~")
    key_dir = os.path.join(home, ".sawtooth", "keys")

    return '{}/{}.priv'.format(key_dir, real_user)


def main(prog_name=os.path.basename(sys.argv[0]), args=None):
    if args is None:
        args = sys.argv[1:]
    parser = create_parser(prog_name)
    args = parser.parse_args(args)

    if args.verbose is None:
        verbose_level = 0
    else:
        verbose_level = args.verbose
    setup_loggers(verbose_level=verbose_level)

    if not args.command:
        parser.print_help()
        sys.exit(1)

    if args.command == 'add_user':
        do_add_user(args)
    elif args.command == 'show_user':
        do_show_user(args)
    elif args.command == 'list':
        do_list(args)
    elif args.command == 'generate':
        do_generate(args)
    elif args.command == 'populate':
        do_populate(args)
    elif args.command == 'load':
        do_load(args)
    elif args.command == 'create_batch':
        do_create_batch(args)
    elif args.command == 'workload':
        do_workload(args)

    else:
        raise CrdtCliException("invalid command: {}".format(args.command))


def main_wrapper():
    # pylint: disable=bare-except
    try:
        main()
    except (CrdtCliException, CrdtClientException) as err:
        print("Error: {}".format(err), file=sys.stderr)
        sys.exit(1)
    except KeyboardInterrupt:
        pass
    except SystemExit as e:
        raise e
    except:
        traceback.print_exc(file=sys.stderr)
        sys.exit(1)
