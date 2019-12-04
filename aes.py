#!/usr/bin/env python3

import sys
import io
import logging
import argparse

from binascii import unhexlify, hexlify
from Crypto.Cipher import AES
from Crypto.Cipher import DES3
from Crypto.Util import Counter

def switch_modes(argument):
    switcher = {
        "ecb" : AES.MODE_ECB,
        "cbc" : AES.MODE_CBC,
        "ctr" : AES.MODE_CTR
    }
    return switcher.get(argument, "invalid mode")

def create_aes_object(mode, key, iv):  
    conv_mode = switch_modes(mode)
    if (conv_mode == AES.MODE_CBC):
        aes_obj = AES.new(unhexlify(key), AES.MODE_CBC, unhexlify(iv))
    elif (conv_mode == AES.MODE_ECB):
        aes_obj = AES.new(unhexlify(key), AES.MODE_ECB)
    else:
        print("Unrecognized aes mode: " + mode)
        return None
    return aes_obj
    
def crypt_buffer(aes_obj, operation, buffer):
    if (operation == "decrypt"):
        return aes_obj.decrypt(unhexlify(buffer))
    if (operation == "encrypt"):
        return aes_obj.encrypt(unhexlify(buffer))

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Process AES Crypto Operations')
    parser.add_argument("--operation", help= "Operation Type encryption or decryption")
    parser.add_argument("--mode", help="Aes mode, e.g. CTR, CBC etc..")
    parser.add_argument("--key", help= "Key Value, could be 128/192/256 bits")
    parser.add_argument("--iv", help= "IV Value, 16 bytes, not mandatory e.g. ECB operations")
    parser.add_argument("--buffer", help="Buffer string, expected in hex format")
    args = parser.parse_args()

    aes_obj = create_aes_object(args.mode, args.key, args.iv)
    output = crypt_buffer(aes_obj, args.operation, args.buffer)
    print(hexlify(output))

