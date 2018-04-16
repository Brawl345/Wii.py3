#!/usr/bin/env python3
import hashlib

from Crypto.Cipher import AES


def align(x, boundary):
    while x % boundary != 0:
        x += 1
    return x


def replace_in_string(string, index, repl):
    """Replaces index num in string with repl."""
    return string[:index] + repl + string[index + 1:]


def pad_blocksize(value, block=64):
    """Pads value to blocksize

    Args:
        value (bytes): Value to pad
        block (int): Block size (Default: 64)
    """
    if len(value) % block != 0:
        value += b"\x00" * (block - (len(value) % block))
    return value


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

    @classmethod
    def generate_checksum(cls, data):
        """Generates a checksum for NANDBOOTINFO, nwc24msg.cfg and probably more.
        Make sure to pass data without the checksum!

        Checksum calculation goes like this:
        1) Break the entire file into 4 byte groups (without the checksum)
        2) Convert the bytes into an integer and add them all together
        3) Grab the lower 32 bits
        Reference: https://github.com/RiiConnect24/RiiConnect24-Mail-Patcher-Windows/blob/master/mailparse.rb#L61-L82
        """
        checksum = 0
        for block in range(0, len(data), 4):
            b = data[block:block + 4]
            checksum += int.from_bytes(b, byteorder='big')
        checksum &= 0xFFFFFFFF
        return checksum
