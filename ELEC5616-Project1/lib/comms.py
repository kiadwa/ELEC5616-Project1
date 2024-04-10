import struct
import secrets
import hmac
import hashlib

from dh import create_dh_key, calculate_dh_secret
from .xor import XOR
from lib.helpers import appendMac, macCheck, appendSalt, generate_random_string

class StealthConn(object):
    def __init__(self, conn, client=False, server=False, verbose=False):
        self.conn = conn
        self.client = client
        self.server = server
        self.verbose = True  # verbose
        self.shared_secret = None
        self.initiate_session()

    def initiate_session(self):
        # Perform the initial connection handshake for agreeing on a shared secret
        if self.server or self.client:
            my_public_key, my_private_key = create_dh_key()
            # Send them our public key
            self.send(bytes(str(my_public_key), "ascii"))
            # Receive their public key
            their_public_key = int(self.recv())
            # Obtain our shared secret
            self.shared_secret = calculate_dh_secret(their_public_key, my_private_key)
            print("Shared hash: {}".format(self.shared_secret.hex()))

    def send(self, data):
        if self.shared_secret:
            # Encrypt the message
            cipher = XOR(self.shared_secret)
            encrypted_data = cipher.encrypt(data)

            # Generate HMAC
            hmac_value = hmac.new(self.shared_secret, encrypted_data, hashlib.sha256).digest()

            # Append HMAC to the encrypted data
            data_to_send = hmac_value + encrypted_data

            if self.verbose:
                print("Original message : {}".format(data))
                print("Encrypted data: {}".format(repr(encrypted_data)))
                print("HMAC: {}".format(repr(hmac_value)))
                print("Sending packet of length: {}".format(len(data_to_send)))
        else:
            data_to_send = data

        # Encode the data's length into an unsigned two byte int ('H')
        pkt_len = struct.pack("H", len(data_to_send))
        self.conn.sendall(pkt_len)
        self.conn.sendall(data_to_send)

    def recv(self):
        # Decode the data's length from an unsigned two byte int ('H')
        pkt_len_packed = self.conn.recv(struct.calcsize("H"))
        unpacked_contents = struct.unpack("H", pkt_len_packed)
        pkt_len = unpacked_contents[0]

        if self.shared_secret:
            received_data = self.conn.recv(pkt_len)

            # Separate HMAC from the received data
            hmac_received = received_data[:32]  # Assuming SHA-256 is used for HMAC
            encrypted_data = received_data[32:]

            # Verify HMAC
            hmac_calculated = hmac.new(self.shared_secret, encrypted_data, hashlib.sha256).digest()
            if not hmac.compare_digest(hmac_received, hmac_calculated):
                raise ValueError("HMAC verification failed")

            # Decrypt the data
            cipher = XOR(self.shared_secret)
            original_msg = cipher.decrypt(encrypted_data)

            if self.verbose:
                print("Receiving message of length: {}".format(len(encrypted_data)))
                print("Encrypted data: {}".format(repr(encrypted_data)))
                print("Original message: {}".format(original_msg))
        else:
            original_msg = self.conn.recv(pkt_len)

        return original_msg

    def close(self):
        self.conn.close()
