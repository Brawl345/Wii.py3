#!/usr/bin/env python3
import array
import os
import socket
import string
from binascii import hexlify, unhexlify

from Struct import Struct
from common import *


class NetConfig:
    """This class performs network configuration. The file is located in /shared2/sys/net/02/config.dat.
       Reference: http://wiibrew.org/wiki//shared2/sys/net/02/config.dat

    Args:
        conf (str): Path to config.dat (will create one if it doesn't exist)
    """

    class ConfigHeader(Struct):
        __endian__ = Struct.BE

        def __format__(self, func=None):
            self.padding = Struct.uint8[4]
            self.connected = Struct.uint8
            self.unknown = Struct.uint8
            self.padding_2 = Struct.uint8[2]

    class ConfigEntry(Struct):

        class ProxySettings(Struct):
            __endian__ = Struct.BE

            def __format__(self, func=None):
                self.useProxy = Struct.uint8
                self.useProxyUserAndPass = Struct.uint8
                self.padding_1 = Struct.string(2)
                self.proxyServer = Struct.string(255)
                self.padding_2 = Struct.uint8
                self.proxyPort = Struct.uint16
                self.proxyUsername = Struct.string(32)
                self.padding_3 = Struct.uint8
                self.proxyPassword = Struct.string(32)

        __endian__ = Struct.BE

        def __format__(self, func=None):
            # General
            self.flags = Struct.uint8
            self.padding_1 = Struct.string(3)
            self.wiiIP = Struct.uint8[4]
            self.subnetMask = Struct.uint8[4]
            self.gateway = Struct.uint8[4]
            self.primaryDNS = Struct.uint8[4]
            self.secondaryDNS = Struct.uint8[4]
            self.padding_2 = Struct.string(2)
            self.mtu = Struct.uint16
            self.padding_3 = Struct.string(8)

            # Proxy
            self.proxy = self.ProxySettings()
            self.padding_4 = Struct.uint8
            self.proxyCopy = self.ProxySettings()
            self.padding_5 = Struct.string(1297)

            # Wireless
            self.ssid = Struct.string(32)
            self.padding_6 = Struct.uint8
            self.ssid_len = Struct.uint8
            self.padding_7 = Struct.string(2)
            self.padding_8 = Struct.uint8
            self.encryption = Struct.uint8
            self.padding_9 = Struct.string(2)
            self.padding_10 = Struct.uint8
            self.key_len = Struct.uint8
            self.wep_key_in_hex = Struct.uint8
            self.padding_11 = Struct.uint8
            self.key = Struct.string(64)
            self.padding_12 = Struct.string(236)

    def __init__(self, conf):
        self.f = conf
        if not os.path.isfile(self.f):
            fp = open(self.f, "wb")
            fp.write(b"\x00\x00\x00\x00\x01\x07\x00\x00")
            fp.write(b"\x00" * 0x91C * 3)
            fp.close()
        fp = open(self.f, "rb")
        self.hdr = self.ConfigHeader().unpack(fp.read(8))
        self.connections = []
        for slot in range(3):
            fp.seek(8 + (0x91C * slot))
            self.connections.append(self.ConfigEntry().unpack(fp.read(0x91C)))
            self.connections[slot].flags_binary = bin(self.connections[slot].flags)[2:].zfill(8)

    def is_blank(self, slot):
        """Returns True if specific config slot is blank.

        Args:
            slot (int): Network slot (1-3)
        """
        if not 1 <= slot <= 3:
            raise ValueError("Out of bounds!")
        slot -= 1
        if self.connections[slot].flags == 0:
            return True
        else:
            return False

    def is_selected(self, slot):
        """Returns 1 if connection is selected."""
        if self.is_blank(slot):
            return None
        slot -= 1
        return int(self.connections[slot].flags_binary[0])

    def is_active(self, slot):
        """Returns 1 if connection passed the connection test."""
        if self.is_blank(slot):
            return None
        slot -= 1
        return int(self.connections[slot].flags_binary[2])

    def get_ssid(self, slot):
        """Returns the SSID from the specified slot."""
        if self.is_blank(slot):
            return None
        slot -= 1
        return self.connections[slot].ssid[:self.connections[slot].ssid_len]

    def get_key(self, slot):
        """Returns the key/password from the specified slot."""
        if self.is_blank(slot):
            return None
        slot -= 1
        if self.connections[slot].encryption != 0:
            if self.connections[slot].encryption > 2:  # WPA
                return self.connections[slot].key[:self.connections[slot].key_len]
            else:  # WEP
                if self.connections[slot].encryption == 1:
                    wep_len = 20
                elif self.connections[slot].encryption == 2:
                    wep_len = 52
                else:
                    raise Exception("Invalid Crypo type: {0}".format(self.connections[slot].encryption))
                if self.connections[slot].wep_key_in_hex:  # WEP with key in HEX
                    wep_key = hexlify(self.connections[slot].key[:wep_len])
                else:  # WEP with key in ASCII
                    wep_key = self.connections[slot].key[:wep_len]
                return wep_key[:(len(wep_key) // 4)]
        else:
            return None

    def get_encryption_type(self, slot):
        """Returns the encryption type from the specified slot."""
        if self.is_blank(slot):
            return None
        slot -= 1
        if self.connections[slot].encryption == 0:
            key_type = "OPEN"
        elif self.connections[slot].encryption == 1:
            key_type = "WEP64"
        elif self.connections[slot].encryption == 2:
            key_type = "WEP128"
        elif self.connections[slot].encryption == 4:
            key_type = "WPA (TKIP)"
        elif self.connections[slot].encryption == 5:
            key_type = "WPA2 (AES)"
        elif self.connections[slot].encryption == 6:
            key_type = "WPA (AES)"
        else:
            print("Invalid crypto type: {0}".format(self.connections[slot].encryption))
            return None
        return key_type

    def get_ip_type(self, slot):
        """Returns the IP type (0 = manual, 1 = DHCP)."""
        if self.is_blank(slot):
            return None
        slot -= 1
        return int(self.connections[slot].flags_binary[6])

    def get_dns_type(self, slot):
        """Returns the DNS type (0 = manual, 1 = DHCP)."""
        if self.is_blank(slot):
            return None
        slot -= 1
        return int(self.connections[slot].flags_binary[5])  # 6 according to WiiBrew, seems kinda wonky...

    def get_connection_type(self, slot):
        """Returns the connection type (0 = wireless, 1 = wired)."""
        if self.is_blank(slot):
            return None
        slot -= 1
        return int(self.connections[slot].flags_binary[7])

    def clear_slot(self, slot):
        """Deletes config from slot number."""
        if self.is_blank(slot):
            return None
        slot -= 1
        file = open(self.f, "rb+")
        file.seek(8 + (0x91C * slot))
        file.write(b"\x00" * 0x91C)
        file.close()

    def select_slot(self, slot):
        """Selects config in slot number."""
        if self.is_selected(slot):
            return None
        slot -= 1
        file = open(self.f, "rb+")

        # Deselect previous network slot
        for s in range(3):
            if self.is_selected(s + 1):
                file.seek(8 + (0x91C * s))
                new_flag = replace_in_string(self.connections[s].flags_binary, 0, '0')
                new_flag = hex(int('0b' + new_flag, 2))[2:]
                file.write(unhexlify(new_flag))

        # Select network slot
        file.seek(8 + (0x91C * slot))
        new_flag = replace_in_string(self.connections[slot].flags_binary, 0, '1')
        new_flag = hex(int('0b' + new_flag, 2))[2:]
        file.write(unhexlify(new_flag.zfill(2)))
        file.close()

    def set_status(self, slot, active=True):
        """Sets internet connection test to passed (True) or failed (False) for slot."""
        if not 1 <= slot <= 3:
            raise ValueError("Out of bounds!")
        slot -= 1
        file = open(self.f, "rb+")

        file.seek(8 + (0x91C * slot))
        if active:
            new_flag = replace_in_string(self.connections[slot].flags_binary, 2, '1')
        else:
            new_flag = replace_in_string(self.connections[slot].flags_binary, 2, '0')
        new_flag = hex(int('0b' + new_flag, 2))[2:]
        file.write(unhexlify(new_flag.zfill(2)))
        file.close()

    def set_connection_type(self, slot, wireless=True):
        """Sets connection type of slot to wireless (True) or wired (False)."""
        if not 1 <= slot <= 3:
            raise ValueError("Out of bounds!")
        slot -= 1
        file = open(self.f, "rb+")

        file.seek(8 + (0x91C * slot))
        if wireless:
            new_flag = replace_in_string(self.connections[slot].flags_binary, 7, '0')
        else:
            new_flag = replace_in_string(self.connections[slot].flags_binary, 7, '1')
        new_flag = hex(int('0b' + new_flag, 2))[2:]
        file.write(unhexlify(new_flag.zfill(2)))
        file.close()

    def set_ip_type(self, slot, dhcp=True):
        """Sets IP type of slot to automatic (True) or manual (False)."""
        if not 1 <= slot <= 3:
            raise ValueError("Out of bounds!")
        slot -= 1
        file = open(self.f, "rb+")

        file.seek(8 + (0x91C * slot))
        if dhcp:
            new_flag = replace_in_string(self.connections[slot].flags_binary, 6, '1')
        else:
            new_flag = replace_in_string(self.connections[slot].flags_binary, 6, '0')
        new_flag = hex(int('0b' + new_flag, 2))[2:]
        file.write(unhexlify(new_flag.zfill(2)))
        file.close()

    def set_dns_type(self, slot, dhcp=True):
        """Sets DNS type of slot to automatic (True) or manual (False)."""
        if not 1 <= slot <= 3:
            raise ValueError("Out of bounds!")
        if self.get_ip_type(slot) == 0 and dhcp:
            raise Exception("IP Type is set to manual, can't set DNS to automatic")

        slot -= 1
        file = open(self.f, "rb+")

        file.seek(8 + (0x91C * slot))
        if dhcp:
            new_flag = replace_in_string(self.connections[slot].flags_binary, 5, '1')
        else:
            new_flag = replace_in_string(self.connections[slot].flags_binary, 5, '0')
        new_flag = hex(int('0b' + new_flag, 2))[2:]
        file.write(unhexlify(new_flag.zfill(2)))
        file.close()

    def set_ssid(self, slot, ssid):
        """Sets SSID of slot"""
        if self.is_blank(slot):
            return None

        if len(ssid) > 32:
            raise Exception("SSID must be < 32 characters")

        slot -= 1
        file = open(self.f, "rb+")

        file.seek(8 + (0x91C * slot) + 1988)
        file.write(pad_blocksize(ssid.encode(), 32))
        file.seek(8 + (0x91C * slot) + 2021)
        file.write(unhexlify("%02X" % len(ssid)))
        file.close()

    def set_encryption(self, slot, encryption):
        """Sets wireless encryption of slot."""
        if self.is_blank(slot):
            return None
        if self.get_connection_type(slot) == 1:
            raise Exception("Connection in slot is wired")

        slot -= 1
        file = open(self.f, "rb+")

        file.seek(8 + (0x91C * slot) + 2025)
        if encryption == "OPEN":
            file.write(b"\x00")
        elif encryption == "WEP64":
            file.write(b"\x01")
        elif encryption == "WEP128":
            file.write(b"\x02")
        elif encryption == "WPA (TKIP)":
            file.write(b"\x04")
        elif encryption == "WPA2 (AES)":
            file.write(b"\x05")
        elif encryption == "WPA (AES)":
            file.write(b"\x06")
        else:
            file.close()
            raise Exception("Invalid crypto type. Valid types are: ``OPEN'', ``WEP64'', ''WEP128'', ``WPA (TKIP)'', "
                            "``WPA2 (AES)'', or ``WPA (AES)''")
        file.close()

    def set_key(self, slot, key):
        """Sets wireless key for slot."""
        if self.is_blank(slot):
            return None
        if self.get_connection_type(slot) == 1:
            raise Exception("Connection in slot is wired")

        if len(key) > 64:
            raise Exception("Key must be <= 64 characters")

        encryption = self.get_encryption_type(slot)

        if encryption == "OPEN":
            raise Exception("Connection is an open network")
        elif encryption == "WEP64":
            wep = True
            if all(c in string.hexdigits for c in key):  # HEX
                if len(key) != 10:
                    raise Exception("HEX key for WEP64 needs to be 10 characters long")
                inhex = True
            else:  # ASCII
                if len(key) != 5:
                    raise Exception("ASCII key for WEP64 needs to be 5 characters long")
                inhex = False
        elif encryption == "WEP128":
            wep = True
            if all(c in string.hexdigits for c in key):  # HEX
                if len(key) != 26:
                    raise Exception("HEX key for WEP128 needs to be 26 characters long")
                inhex = True
            else:  # ASCII
                if len(key) != 13:
                    raise Exception("ASCII key for WEP128 needs to be 13 characters long")
                inhex = False
        else:
            wep = False
            inhex = False

        slot -= 1
        file = open(self.f, "rb+")
        file.seek(8 + (0x91C * slot) + 2029)
        if wep:
            file.write(b"\x00")
            if inhex:
                file.write(b"\x01")
            else:
                file.write(b"\x00")
        else:
            file.write(unhexlify("%02X" % len(key)))
            file.write(b"\x00")

        file.seek(8 + (0x91C * slot) + 2032)
        if wep:
            if inhex:
                file.write(unhexlify(key * 4))
            else:
                file.write(pad_blocksize(key.encode() * 4))
        else:
            file.write(pad_blocksize(key.encode()))

        file.close()

    def set_dns(self, slot, dns, primary=True):
        """Sets DNS for slot."""
        if self.is_blank(slot):
            return None

        slot -= 1
        try:
            dns = socket.inet_aton(dns)
        except OSError:
            raise Exception("IPv4 address is invalid")

        file = open(self.f, "rb+")
        if primary:
            file.seek(8 + (0x91C * slot) + 16)
        else:
            file.seek(8 + (0x91C * slot) + 20)
        file.write(dns)
        file.close()
        self.set_dns_type(slot + 1, False)

    def set_ip(self, slot, ip):
        """Sets IP for slot."""
        if self.is_blank(slot):
            return None

        slot -= 1
        try:
            ip = socket.inet_aton(ip)
        except OSError:
            raise Exception("IPv4 address is invalid")

        file = open(self.f, "rb+")
        file.seek(8 + (0x91C * slot) + 4)
        file.write(ip)
        file.close()
        self.set_ip_type(slot + 1, False)

    def set_subnet(self, slot, ip):
        """Sets Subnet mask for slot."""
        if self.is_blank(slot):
            return None

        slot -= 1
        try:
            ip = socket.inet_aton(ip)
        except OSError:
            raise Exception("IPv4 address is invalid")

        file = open(self.f, "rb+")
        file.seek(8 + (0x91C * slot) + 8)
        file.write(ip)
        file.close()
        self.set_ip_type(slot + 1, False)

    def set_gateway(self, slot, ip):
        """Sets Gateway for slot."""
        if self.is_blank(slot):
            return None

        slot -= 1
        try:
            ip = socket.inet_aton(ip)
        except OSError:
            raise Exception("IPv4 address is invalid")

        file = open(self.f, "rb+")
        file.seek(8 + (0x91C * slot) + 12)
        file.write(ip)
        file.close()
        self.set_ip_type(slot + 1, False)

    def set_mtu(self, slot, mtu):
        """Sets MTU for slot."""
        if self.is_blank(slot):
            return None

        slot -= 1
        if mtu != 0 and not 576 <= mtu <= 1500:
            raise Exception("Invalid MTU - valid values are 0 and 576 up to 1500")

        file = open(self.f, "rb+")
        file.seek(8 + (0x91C * slot) + 26)
        file.write(unhexlify(hex(mtu)[2:].zfill(4)))
        file.close()

    def set_proxy_state(self, slot, active=True, userandpass=False):
        """Sets proxy flag for slot. Set 'userandpass' to True for authentication."""
        if self.is_blank(slot):
            return None

        slot -= 1
        file = open(self.f, "rb+")
        file.seek(8 + (0x91C * slot) + 36)
        if active:
            file.write(b"\x01")
        else:
            file.write(b"\x00")
        if userandpass:
            file.write(b"\x01")
        else:
            file.write(b"\x00")

        file.seek(8 + (0x91C * slot) + 364)
        if active:
            file.write(b"\x01")
        else:
            file.write(b"\x00")
        if userandpass:
            file.write(b"\x01")
        else:
            file.write(b"\x00")

        file.close()

    def set_proxy_server(self, slot, server):
        """Sets proxy server for slot."""
        if self.is_blank(slot):
            return None

        if len(server) > 255:
            raise Exception("Server address must be < 256 characters!")

        slot -= 1
        file = open(self.f, "rb+")
        file.seek(8 + (0x91C * slot) + 40)
        file.write(pad_blocksize(server.encode(), 255))
        file.seek(8 + (0x91C * slot) + 368)
        file.write(pad_blocksize(server.encode(), 255))

        file.close()

    def set_proxy_port(self, slot, port):
        """Sets proxy port for slot."""
        if self.is_blank(slot):
            return None

        if not isinstance(port, int):
            raise ValueError("Port must be an integer")

        if not 0 < port <= 34463:
            raise ValueError("Port must be between 1 and 34463")

        slot -= 1
        file = open(self.f, "rb+")
        file.seek(8 + (0x91C * slot) + 296)
        file.write(unhexlify(hex(port)[2:].zfill(4)))
        file.seek(8 + (0x91C * slot) + 624)
        file.write(unhexlify(hex(port)[2:].zfill(4)))

        file.close()

    def set_proxy_username(self, slot, username):
        """Sets proxy username for slot."""
        if self.is_blank(slot):
            return None

        if len(username) > 32:
            raise Exception("Username must be <= 32 characters!")

        slot -= 1
        file = open(self.f, "rb+")
        file.seek(8 + (0x91C * slot) + 298)
        file.write(pad_blocksize(username.encode(), 32))
        file.seek(8 + (0x91C * slot) + 626)
        file.write(pad_blocksize(username.encode(), 32))

        file.close()

    def set_proxy_password(self, slot, password):
        """Sets proxy password for slot."""
        if self.is_blank(slot):
            return None

        if len(password) > 32:
            raise Exception("Password must be <= 32 characters!")

        slot -= 1
        file = open(self.f, "rb+")
        file.seek(8 + (0x91C * slot) + 331)
        file.write(pad_blocksize(password.encode(), 32))
        file.seek(8 + (0x91C * slot) + 659)
        file.write(pad_blocksize(password.encode(), 32))

        file.close()

    def __repr__(self):
        usedslots = 0
        for slot in range(3):
            if not self.is_blank(slot + 1):
                usedslots += 1
        return "Wii Network Config ({0}/3 Slots used)".format(usedslots)

    def __str__(self):
        output = "Wii Network Config:\n"
        for num, slot in enumerate(self.connections):
            output += "\n  Slot {0}".format(num + 1)
            if self.is_selected(num + 1):
                output += " (selected)"
            output += ":\n"

            if self.is_blank(num + 1):
                output += "    Free\n"
                continue
            if not self.is_active(num + 1):
                output += "    Connection test failed\n"
            if self.get_connection_type(num + 1) == 0:
                output += "    Connection Type: Wireless\n"
                output += "    Encryption Type: {0}\n".format(self.get_encryption_type(num + 1))
                output += "    SSID: {0}\n".format(self.get_ssid(num + 1).decode('latin-1'))
                if slot.encryption >= 1:
                    output += "    Password: {0}\n".format(self.get_key(num + 1).decode('latin-1'))
            elif self.get_connection_type(num + 1) == 1:
                output += "    Connection Type: Wired\n"

            if slot.mtu > 0:
                output += "    MTU: {0}\n".format(slot.mtu)

            if self.get_ip_type(num + 1) == 0:
                output += "\n    IP settings:\n"
                output += "      IP address: {0}\n".format(".".join(map(str, slot.wiiIP)))
                output += "      Subnet mask: {0}\n".format(".".join(map(str, slot.subnetMask)))
                output += "      Gateway: {0}\n".format(".".join(map(str, slot.gateway)))

            if self.get_dns_type(num + 1) == 0:
                output += "\n    DNS settings:\n"
                output += "      Primary DNS: {0}\n".format(".".join(map(str, slot.primaryDNS)))
                output += "      Secondary DNS: {0}\n".format(".".join(map(str, slot.secondaryDNS)))

            if slot.proxy.useProxy:
                output += "\n    Proxy settings:\n"
                output += "      Proxy server: {0}\n".format(slot.proxy.proxyServer.rstrip(b"\x00").decode())
                output += "      Proxy port: {0}\n".format(slot.proxy.proxyPort)
                if slot.proxy.useProxyUserAndPass:
                    output += "      Username: {0}\n".format(slot.proxy.proxyUsername.rstrip(b"\x00").decode('latin-1'))
                    output += "      Password: {0}\n".format(slot.proxy.proxyPassword.rstrip(b"\x00").decode('latin-1'))

        return output


class IplSave:
    """This class perfoms all iplsave.bin related functions, like (re-)moving and adding channels.
       Reference: http://wiibrew.org/wiki//title/00000001/00000002/data/iplsave.bin

    Args:
        f (str): Path to iplsave.bin
    """

    class IplSaveEntry(Struct):
        __endian__ = Struct.BE

        def __format__(self, func=None):
            self.type1 = Struct.uint8
            self.type2 = Struct.uint8
            self.unknown = Struct.uint32
            self.flags = Struct.uint16
            self.titleid = Struct.uint64

        def __repr__(self):
            return "{:08x}{:08x}".format(self.titleid >> 32, self.titleid & 0xFFFFFFFF)

    class IplSaveHeader(Struct):
        __endian__ = Struct.BE

        def __format__(self, func=None):
            self.magic = Struct.string(4)
            self.filesize = Struct.uint32
            self.unknown = Struct.uint64

    def __init__(self, f):
        self.f = f

        try:
            fp = open(f, 'r+b')
        except:
            raise Exception("File could not be opened")
        self.hdr = self.IplSaveHeader().unpack(fp.read(16))
        self.channels = []
        self.usedBlocks = 0
        self.freeBlocks = 0
        for i in range(48):
            self.channels.append(self.IplSaveEntry().unpack(fp.read(16)))
            if self.channels[i].type1 == 0:
                self.freeBlocks += 1
        self.usedBlocks = 48 - self.freeBlocks

        self.footer = fp.read(self.hdr.filesize - 16 - 768 - 16)  # size of file - header - channels - md5
        self.md5 = fp.read(16)
        fp.seek(0)
        if self.md5 != Crypto().create_md5hash(fp.read(self.hdr.filesize - 16)):  # whole file minus md5
            fp.close()
            raise Exception("MD5 Sum mismatch!")
        fp.close()

    def get_free_blocks(self):
        """Returns # of free slots."""
        return self.freeBlocks

    def get_used_blocks(self):
        """Returns # of used slots."""
        return self.usedBlocks

    def is_block_free(self, col, row, page):
        """Returns True if slot in col in row on page is free.

        Args:
            col (int): Column number (1-4)
            row (int): Row number (1-3)
            page (int): Page number (1-4)
        """
        if not 1 <= col <= 4 or not 1 <= row <= 3 or not 1 <= page <= 4:
            raise ValueError("Out of bounds")
        i = ((col - 1) + ((row - 1) * 4) + ((page - 1) * 12))
        if self.channels[i].type1 == 0:
            return True
        return False

    def update_md5(self):
        """Updates the MD5 sum of the file. Used by other functions."""
        fp = open(self.f, "r+b")
        data = fp.read(self.hdr.filesize - 16)
        md5 = Crypto().create_md5hash(data)
        fp.write(md5)
        fp.close()

    def move_title(self, col1, row1, page1, col2, row2, page2):
        """Moves title from col1, row1, page1 to col2, row2, page2"""
        if not 1 <= col1 <= 4 or not 1 <= row1 <= 3 or not 1 <= page1 <= 4:
            raise ValueError("Source is out of bounds")
        if not 1 <= col2 <= 4 or not 1 <= row2 <= 3 or not 1 <= page2 <= 4:
            raise ValueError("Destination is out of bounds")
        if (col1, row1, page1) == (col2, row2, page2):
            raise ValueError("Title is already in this position")

        if self.is_block_free(col1, row1, page1):
            raise Exception("No channel on source tile")
        if not self.is_block_free(col2, row2, page2):
            raise Exception("Destination tile is not free")

        oldpos = ((col1 - 1) + ((row1 - 1) * 4) + ((page1 - 1) * 12))
        newpos = ((col2 - 1) + ((row2 - 1) * 4) + ((page2 - 1) * 12))
        self.channels[oldpos], self.channels[newpos] = self.channels[newpos], self.channels[oldpos]

        fp = open(self.f, "r+b")
        fp.write(self.hdr.pack())
        for i in range(48):
            fp.write(self.channels[i].pack())
        fp.write(self.footer)

        fp.close()
        self.update_md5()

    def sort_by_tid(self):
        """Sorts the whole Wii menu after the lower titleid"""
        fp = open(self.f, "r+b")
        fp.write(self.hdr.pack())
        disc_channel = [x for x in self.channels if x.type1 == 1][0]
        fp.write(disc_channel.pack())

        sorted_channels = sorted(self.channels, key=lambda x: x.titleid & 0xFFFFFFFF)
        freeslots = 0
        for i in sorted_channels:
            if i.type1 == 0:
                freeslots += 1
            elif i.titleid != 0:
                fp.write(i.pack())

        fp.write((b"\x00" * 16) * freeslots)
        fp.write(self.footer)

        fp.close()
        self.update_md5()

    def __repr__(self):
        return "Wii IplSave: {0} slots used out of 48 ({1} free)".format(self.usedBlocks, self.freeBlocks)

    def __str__(self):
        output = "IplSave:\n"
        output += "  Used {0} slots out of 48 ({1} free)\n\n".format(self.usedBlocks, self.freeBlocks)

        for page in range(4):
            output += "  Page {0}:\n    ".format(page + 1)
            for row in range(3):
                for slot in range(4):
                    curtitle = self.channels[(slot + (row * 4) + (page * 12))]
                    if curtitle.titleid == 0:
                        if curtitle.type1 == 1:
                            output += "{0:8}".format("Disc")
                        else:
                            output += "{0:8}".format("Empty")
                    else:
                        ascii_titleid = "{:08x}".format(curtitle.titleid & 0xFFFFFFFF)
                        output += "{0:8}".format(unhexlify(ascii_titleid).decode())
                if row == 2:
                    output += "\n\n"
                else:
                    output += "\n    "
        return output


class VFF:
    """This class performs all VFF-related actions such as dumping files from the FAT filesystem and directory listing.
       Reference: http://wiibrew.org/wiki/VFF

       Original code by marcan

    Args:
        f (str): Path to a Wii VFF
    """

    class VFFHeader(Struct):
        __endian__ = Struct.BE

        def __format__(self, func=None):
            self.magic = Struct.string(4)
            self.unknown = Struct.uint8[2]
            self.unknown_2 = Struct.uint8[2]
            self.filesize = Struct.uint32
            self.headersize = Struct.uint16
            self.padding = Struct.string(18)

    class FAT:
        """"Represents the FAT filesystem(s) in the VFF file."""

        def __init__(self, fp, clustercount):
            if clustercount < 4085:
                # FAT12
                self.fat = 12
                fatsize = ((clustercount + 1) // 2) * 3
                self.reserved = 0xff0
                code = 'B'
            elif clustercount < 65525:
                # FAT16
                self.fat = 16
                self.reserved = 0xfff0
                fatsize = clustercount * 2
                code = 'H'
            else:
                raise Exception("FAT type not supported")

            self.clustersize = 0x200
            data = fp.read((fatsize + self.clustersize - 1) & ~(self.clustersize - 1))
            self.array = array.array(code, data)

        def is_available(self, x):
            return x == 0x0000

        def is_used(self, x):
            return 0x0001 <= x < self.reserved

        def is_reserved(self, x):
            return self.reserved <= x <= (self.reserved + 6)

        def is_bad(self, x):
            return x == (self.reserved + 7)

        def is_last(self, x):
            return (self.reserved + 8) <= x

        def get_chain(self, start):
            chain = []
            clus = start
            while self.is_used(clus):
                chain.append(clus)
                clus = self[clus]
            if not self.is_last(clus):
                raise Exception("Found 0x%04x in cluster chain" % clus)
            return chain

        def __getitem__(self, item):
            if self.fat == 16:
                return self.array[item]
            else:
                off = (item // 2) * 3
                if item & 1:
                    return (self.array[off + 1] >> 4) | (self.array[off + 2] << 4)
                else:
                    return self.array[off] | ((self.array[off + 1] & 0xf) << 8)

    class Directory:
        """Represents the directory table of the FAT file system.
           Reference: https://en.wikipedia.org/wiki/Design_of_the_FAT_file_system#Directory_table
        """

        # FAT Attributes
        # Reference: https://en.wikipedia.org/wiki/Design_of_the_FAT_file_system#DIR_OFS_0Bh
        A_R = 1  # Read only
        A_H = 2  # Hidden
        A_S = 4  # System file
        A_VL = 8  # Volume Label
        A_DIR = 16  # Directory
        A_A = 32  # Archive
        A_DEV = 64  # Device

        class FileEntry(Struct):
            def __format__(self, format_spec=None):
                self.name = Struct.string(8)
                self.file_ext = Struct.string(3)
                self.attributes = Struct.uint8
                self.reserved = Struct.uint8
                self.creationTimeSeconds = Struct.uint8
                self.creationTime = Struct.uint16
                self.creationDate = Struct.uint16
                self.accessDate = Struct.uint16
                self.extendedAttributes = Struct.uint16
                self.lastModifiedTime = Struct.uint16
                self.lastModifiedDate = Struct.uint16
                self.start = Struct.uint16
                self.fileSize = Struct.uint32

        def __init__(self, vff, data):
            self.vff = vff
            self.data = data

        def read(self):
            files = []
            for i in range(0, len(self.data), 32):
                entry = self.data[i:i + 32]
                file = self.FileEntry().unpack(entry)
                if file.name[0] in b"\xe5\x00":  # 0x00 = Empty, 0xe5 = deleted
                    continue
                # https://doc.micrium.com/display/TECHOV/FAT+Organization#FATOrganization-Entriesforfilesthathavelongfilenames
                if file.attributes & 0xf == 0xf:
                    continue
                fullname = file.name.rstrip().decode() + "." + file.file_ext.rstrip().decode()
                if fullname[-1] == ".":
                    fullname = fullname[:-1]
                files.append((fullname, file.attributes, file.start, file.fileSize))
            return files

        def ls(self, pre=""):
            for name, attr, start, size in self.read():
                if attr & self.A_DIR:
                    if name in [".", ".."]:
                        continue
                    print("{0}/{1}/".format(pre, name))
                    self[name].ls("{0}/{1}".format(pre, name))
                else:
                    print("{0}/{1} [{2} bytes]".format(pre, name, size))

        def dump(self, path):
            if not os.path.isdir(path):
                os.mkdir(path)
            for name, attr, start, size in self.read():
                if attr & self.A_DIR:

                    if name in [".", ".."]:
                        continue
                    print(" {0}/{1}/".format(path, name))
                    self[name].dump("{0}/{1}".format(path, name))
                else:
                    print(" {0}/{1} [{2} bytes]".format(path, name, size))
                    f = open("{0}/{1}".format(path, name), "wb")
                    f.write(self[name])
                    f.close()

        def __getitem__(self, d):
            for name, attr, start, size in self.read():
                if name.lower() == d.lower():
                    if attr & self.A_DIR:
                        return VFF.Directory(self.vff, self.vff.read_chain(start))
                    elif not size:
                        return ""
                    else:
                        return self.vff.read_chain(start)[:size]

    def __init__(self, f):
        self.f = f
        try:
            self.fp = open(f, 'r+b')
        except FileNotFoundError:
            raise FileNotFoundError("File not found")

        self.hdr = self.VFFHeader().unpack(self.fp.read(0x20))
        if self.hdr.magic != b"VFF ":
            self.fp.close()
            raise Exception("Magic word is wrong, should be 'VFF '")

        self.clustersize = 0x200
        self.clustercount = self.hdr.filesize // self.clustersize

        self.fat1 = self.FAT(self.fp, self.clustercount)
        self.fat2 = self.FAT(self.fp, self.clustercount)

        self.root = self.Directory(self, self.fp.read(0x1000))
        self.offset = self.fp.tell()

    def read_cluster(self, num):
        num -= 2
        self.fp.seek(self.offset + self.clustersize * num)
        clus = self.fp.read(self.clustersize)
        return clus

    def read_chain(self, start):
        clusters = self.fat1.get_chain(start)
        data = b""
        for c in clusters:
            data += self.read_cluster(c)
        return data

    def __repr__(self):
        return "Wii VFF: {0} bytes with {1} clusters (FAT{2})".format(self.hdr.filesize, self.clustercount,
                                                                      self.fat1.fat)

    def __str__(self):
        output = "VFF:\n"
        output += "  Size: {0} bytes\n".format(self.hdr.filesize)
        output += "  Cluster size: {0}\n".format(self.clustersize)
        output += "  Number of clusters: {0}\n".format(self.clustercount)
        output += "  FAT type: FAT{0}\n".format(self.fat1.fat)

        return output
