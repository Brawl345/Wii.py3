#!/usr/bin/env python3
import os
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
        # TODO: Return None for LAN?
        # TODO: What about the Wi-Fi-Connector?
        if self.is_blank(slot):
            return None
        slot -= 1
        return self.connections[slot].ssid[:self.connections[slot].ssid_len]

    def get_key(self, slot):
        """Returns the key/password from the specified slot."""
        # TODO: Return None for LAN?
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
        # TODO: Check for LAN/Wifi-Connector and return None
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
        file.write(ssid.encode())
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
            raise Exception("Key must be < 64 characters")

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
            file.write(key.encode())

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
