#!/usr/bin/env python3
import hashlib

from Crypto.Cipher import AES


def align(x, boundary):
    while x % boundary != 0:
        x += 1
    return x


class Crypto:
    """"This is a Cryptographic/hash class used to abstract away things (to make changes easier)"""
    align = 64

    @classmethod
    def decrypt_data(cls, key, iv, data, align=True):
        """Decrypts some data (aligns to 64 bytes, if needed)."""
        if (len(data) % cls.align) != 0 and align:
            return AES.new(key, AES.MODE_CBC, iv).decrypt(data + (b"\x00" * (cls.align - (len(data) % cls.align))))
        else:
            return AES.new(key, AES.MODE_CBC, iv).decrypt(data)

    @classmethod
    def encrypt_data(cls, key, iv, data, align=True):
        """Encrypts some data (aligns to 64 bytes, if needed)."""
        if (len(data) % cls.align) != 0 and align:
            return AES.new(key, AES.MODE_CBC, iv).encrypt(data + (b"\x00" * (cls.align - (len(data) % cls.align))))
        else:
            return AES.new(key, AES.MODE_CBC, iv).encrypt(data)

    @classmethod
    def create_md5hash_hex(cls, data):
        return hashlib.md5(data).hexdigest()

    @classmethod
    def create_md5hash(cls, data):
        return hashlib.md5(data).digest()
