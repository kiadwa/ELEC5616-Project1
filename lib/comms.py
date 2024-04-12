import struct
import secrets
import Crypto.Cipher
import dh

from Crypto.Cipher import AES;
from Crypto.Util.Padding import pad
from Crypto.Util.Padding import unpad;
from Crypto.Random import get_random_bytes
from dh.__init__ import create_dh_key, calculate_dh_secret
from lib.helpers import appendMac, macCheck, appendSalt, generate_random_string


class StealthConn(object):
    def __init__(self, conn, client=False, server=False, verbose=False):
        self.conn = conn
        self.client = client
        self.server = server
        self.verbose = True  # verbose
        self.shared_secret = None
        self.initiate_session()
        self.iv = b'\x31' * 16
        self.nonces = set()
        
    def initiate_session(self):
        # Perform the initial connection handshake for agreeing on a shared secret 
        # This can be broken into code run just on the server or just on the client
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
            # Project TODO: Is XOR the best cipher here? Why not? Use a more secure cipher (from the pycryptodome library)
            
            #generate nonce for replay attack detection
            nonce = secrets.token_bytes(16)

            #added MAC to the message to send
            padded = pad(data + nonce, AES.block_size)
            cipher = AES.new(self.shared_secret, AES.MODE_CBC, self.iv)
            #set up cipher and its mode then encrypt
            encrypted = cipher.encrypt(padded)
            #append HMAC
            data_to_send = appendMac(encrypted, self.shared_secret)

            if self.verbose:
                print()
                print("Original message : {}".format(data))
                print("Encrypted data: {}".format(repr(data_to_send)))
                print("Sending packet of length: {}".format(len(data_to_send)))
                print("HMAC: {}".format(data_to_send[-32:]))
                print()
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
            encrypted_data = self.conn.recv(pkt_len)
            #separate HMAC
            received_mac = encrypted_data[-32:]
            #separate cipher text
            noMac_data= encrypted_data[:-32]
            mac_verified = macCheck(noMac_data, received_mac, self.shared_secret)
            #HMAC authentication
            if not mac_verified:
                raise Exception("MAC verification failed!")
            
            #prepare for decrytion
            cipher = AES.new(self.shared_secret, AES.MODE_CBC, self.iv)

            decrypted = cipher.decrypt(noMac_data)

            msg_withn_once = unpad(decrypted, AES.block_size)

            #separate nonce to verify potential replay attack risk
            original_msg = msg_withn_once[:-16]
            nonce = original_msg[-16:]
            if nonce in self.nonces:
                raise Exception("Potential Replay Attack detected!")
            else:
                self.nonces.add(nonce)
                
            if self.verbose:
                print()
                print("Receiving message of length: {}".format(len(encrypted_data)))
                print("Encrypted data: {}".format(repr(encrypted_data)))
                print("Original message: {}".format(original_msg))
                print()

        else:
            original_msg = self.conn.recv(pkt_len)

        return original_msg

    def close(self):
        self.conn.close()


