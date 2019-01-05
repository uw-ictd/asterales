import cbor
import requests

import nacl.signing
import nacl.encoding


signing_key = nacl.signing.SigningKey.generate()
verify_key = signing_key.verify_key

data = {'network_id': '12345',
        'key': verify_key.encode(encoder=nacl.encoding.RawEncoder)
        }

data_encoded = cbor.dumps(data)

signed_message = signing_key.sign(data_encoded)

message = {'network_sig': signed_message.signature,
           'msg': signed_message.message}

encoded_message = cbor.dumps(message)

res = requests.post(url="http://localhost:5000/register/network",
                    data=encoded_message,
                    headers={'Content-Type': 'application/octet-stream'})

print(res)
for line in res.iter_lines():
    print(line)
