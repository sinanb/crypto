#!/usr/bin/env python3

import sys
import io
import argparse

from binascii import unhexlify, hexlify
from Crypto.Cipher import AES
from Crypto.Cipher import DES3
from Crypto.Util import Counter

def switch_modes(argument, algo):
    switcher = {
        "ecb" : algo.MODE_ECB,
        "cbc" : algo.MODE_CBC,
        "ctr" : algo.MODE_CTR
     }
    return switcher.get(argument, "invalid mode")

def switch_algo(argument):
    switcher = {
        "aes" : AES,
        "tdes" : DES3
     }
    return switcher.get(argument, "invalid mode")

def create_crypto_object(algo, mode, key, iv):
    conv_algo = switch_algo(algo)
    conv_mode = switch_modes(mode, conv_algo)
    if (conv_mode == conv_algo.MODE_CBC):
        aes_obj = conv_algo.new(key, conv_mode, iv)
    elif (conv_mode == conv_algo.MODE_ECB):
        aes_obj = conv_algo.new(key, conv_mode)
    elif (conv_mode == conv_algo.MODE_CTR):
        cnt = Counter.new(128, initial_value=0)
        aes_obj = conv_algo.new(key, conv_mode, counter=cnt)
    else:
        print("Unrecognized aes mode: " + mode)
        return None
    return aes_obj
    
def crypt_buffer(obj, operation, buffer):
    if (operation == "decrypt"):
        return obj.decrypt(buffer)
    if (operation == "encrypt"):
        return obj.encrypt(buffer)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Process AES Crypto Operations')
    parser.add_argument("--operation", help="Operation Type", choices=["decrypt","encrypt"], required=True)
    parser.add_argument("--algo", help="Algo Mode", choices=["aes","tdes"], required=True)
    parser.add_argument("--mode", help="Cryption Mode", choices=["ecb","cbc","ctr"], default="ecb")
    parser.add_argument("--key", help= "Key Value, could be 128/192/256 bits", required=True)
    parser.add_argument("--iv", help= "IV Value, 16 bytes, not mandatory e.g. ECB and CTR operations")
    parser.add_argument("--buffer", help="Buffer string, expected in hex format", required=True)
    args = parser.parse_args()

    obj = create_crypto_object(args.algo, args.mode, unhexlify(args.key), unhexlify(args.iv))
    output = crypt_buffer(obj, args.operation, unhexlify(args.buffer))
    print(hexlify(output))
