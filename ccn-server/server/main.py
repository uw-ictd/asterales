import logging
import nacl.encoding
import nacl.signing

import cbor
from flask import Flask
from flask import request

app = Flask(__name__)

@app.route('/')
def hello_world():
    assert request.path == "/"
    return 'Hello, World!'


@app.route('/register/user', methods=['POST'])
def register_user():
    raise NotImplementedError()


@app.route('/register/network', methods=['POST'])
def register_network():
    app.logger.debug("got register network")
    app.logger.debug("Method is %s", request.method)
    app.logger.debug(request.mimetype)
    app.logger.debug(request.content_type)
    app.logger.debug(request.content_encoding)
    # Parse the outer data layer from wire format
    data = cbor.loads(request.data)
    raw_message = data['msg']
    signature = data['network_sig']

    # Parse the inner message from wire format
    message = cbor.loads(raw_message)
    key = nacl.signing.VerifyKey(message['key'], encoder=nacl.encoding.RawEncoder)
    verified = key.verify(raw_message, signature, encoder=nacl.encoding.RawEncoder)

    app.logger.info("Verified? %s", verified)
    if not verified:
        raise IndexError()

    return "Network key was verified."


@app.route('/user/<user_id>')
def existing_user(user_id):
    raise NotImplementedError()


@app.route('/status/backhaul')
def backhaul_status():
    raise NotImplementedError()


def initialize_crdt_key():
    try:
        with open("crdt_network_key.priv", "rb") as f:
            logging.debug("loading signing key from file")
            key_data = f.read()
            signing_key = nacl.signing.SigningKey(key_data, encoder=nacl.encoding.RawEncoder)
    except FileNotFoundError:
        logging.warning("no key file present, generating new network signing key")
        signing_key = nacl.signing.SigningKey.generate()
        key_data = signing_key.encode(encoder=nacl.encoding.RawEncoder)
        with open("crdt_network_key.priv", "w+b") as f:
            f.write(key_data)

    return signing_key, signing_key.verify_key


if __name__ == "__main__":
    logging.getLogger().setLevel(logging.DEBUG)
    signing_key, verify_key = initialize_crdt_key()
    signed_message = signing_key.sign(b'hello')
    print("signed message")
    print(signed_message)
    print(signed_message.signature)
    print(signed_message.message)
    # TODO(matt9j) Remove debug flag before deployment
    app.run(debug=True, host='0.0.0.0', port=5000)
