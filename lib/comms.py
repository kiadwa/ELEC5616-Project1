import struct
import secrets
import Crypto.Cipher


from Crypto.Cipher import AES;
from lib import create_dh_key, calculate_dh_secret
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
        
    def encrypt(self, message):
        cipher = AES.new(message, AES.MODE_CBC)
        padMessage = self.pad(message)
        cipherTxt = cipher.encrypt(padMessage)
        iv = cipher.iv
        return [cipherTxt, iv]
    def decrypt(self, cipherText, iv, message):
        cipher = AES.new(message, AES.MODE_CBC, iv)
        decrypted = cipher.decrypt(cipherText)
        decrypted_depad = self.unpad(decrypted)
        return decrypted_depad
    def pad(self, data):
        padLength = AES.block_size - (len(data) % AES.block_size)
        padded = data + bytes([padLength]) * padLength
        return padded
    def removePad(self,data):
        padLength = data[-1]
        rePad = data[:-padLength]
        return rePad

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
            cipher = AES.new(self.shared_secret, AES.MODE_CBC)
            data_to_send = self.encrypt(data)
            if self.verbose:
                print()
                print("Original message : {}".format(data))
                print("Encrypted data: {}".format(repr(data_to_send[0])))
                print("Sending packet of length: {}".format(len(data_to_send[0])))
                print()
        else:
            data_to_send = data

        # Encode the data's length into an unsigned two byte int ('H')
        pkt_len = struct.pack("H", len(data_to_send[0]))
        self.conn.sendall(pkt_len)
        self.conn.sendall(data_to_send)

    def recv(self):
        # Decode the data's length from an unsigned two byte int ('H')
        pkt_len_packed = self.conn.recv(struct.calcsize("H"))
        unpacked_contents = struct.unpack("H", pkt_len_packed)
        pkt_len = unpacked_contents[0]

        if self.shared_secret:

            encrypted_data = self.conn.recv(pkt_len)
            # Project TODO: as in send(), change the cipher here.
            cipher = AES(self.shared_secret, AES.MODE_CBC)
            original_msg = cipher.decrypt(encrypted_data)

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
