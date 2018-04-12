#!/usr/bin/env python3
import os
from binascii import hexlify

from hexdump import dump

from Struct import Struct
from common import *


class Savegame:
    """Represents a savegame.
       Reference: http://wiibrew.org/wiki/Savegame_Files

    Args:
        f (str): Path to data.bin
    """

    class SavegameHeader(Struct):
        """http://wiibrew.org/wiki/Savegame_Files#Main_header"""
        __endian__ = Struct.BE

        def __format__(self, func=None):
            self.savegameId = Struct.uint32[2]  # TODO: Struct.uint64?
            self.bannerSize = Struct.uint32
            self.permissions = Struct.uint8
            self.unknown1 = Struct.uint8
            self.md5hash = Struct.string(16)
            self.unknown2 = Struct.uint16

    class SavegameBanner(Struct):
        """http://wiibrew.org/wiki/Savegame_Files#Banner"""
        __endian__ = Struct.BE

        def __format__(self, func=None):
            self.magic = Struct.string(4)
            self.flags = Struct.uint32
            self.animSpeed = Struct.uint16
            self.reserved = Struct.uint32[5]
            self.gameTitle = Struct.string(64)
            self.gameSubTitle = Struct.string(64)
            self.banner = Struct.string(24576)
            self.icon0 = Struct.string(4608)
            self.icon1 = Struct.string(4608)
            self.icon2 = Struct.string(4608)
            self.icon3 = Struct.string(4608)
            self.icon4 = Struct.string(4608)
            self.icon5 = Struct.string(4608)
            self.icon6 = Struct.string(4608)
            self.icon7 = Struct.string(4608)

    class BackupHeader(Struct):
        """http://wiibrew.org/wiki/Savegame_Files#Bk_.28.22BacKup.22.29_Header"""
        __endian__ = Struct.BE

        def __format__(self, func=None):
            self.hdrSize = Struct.uint32
            self.magic = Struct.string(2)
            self.version = Struct.uint16
            self.NGid = Struct.uint32
            self.filesCount = Struct.uint32
            self.filesSize = Struct.uint32
            self.unknown1 = Struct.uint32
            self.unknown2 = Struct.uint32
            self.totalSize = Struct.uint32
            self.unknown3 = Struct.uint8[64]
            self.unknown4 = Struct.uint32
            self.gameId = Struct.string(4)
            self.wiiMacAddr = Struct.uint8[6]
            self.unknown6 = Struct.uint16
            self.padding = Struct.uint32[4]

    class FileHeader(Struct):
        """http://wiibrew.org/wiki/Savegame_Files#File_Header"""
        __endian__ = Struct.BE

        def __format__(self, func=None):
            self.magic = Struct.string(4)
            self.size = Struct.uint32
            self.permissions = Struct.uint8
            self.attribute = Struct.uint8
            self.type = Struct.uint8
            self.namedata = Struct.string(0x45)

    def __init__(self, f):
        self.sdKey = b"\xAB\x01\xB9\xD8\xE1\x62\x2B\x08\xAF\xBA\xD8\x4D\xBF\xC2\xA5\x5D"
        self.sdIv = b"\x21\x67\x12\xE6\xAA\x1F\x68\x9F\x95\xC5\xA2\x23\x24\xDC\x6A\x98"
        self.md5Blanker = b"\x0E\x65\x37\x81\x99\xBE\x45\x17\xAB\x06\xEC\x22\x45\x1A\x57\x93"

        self.f = f
        try:
            self.file = open(f, 'r+b')
        except FileNotFoundError:
            raise FileNotFoundError("File not found")

        self.iconCount = 1
        headerbuffer = self.file.read(0xF0C0)
        headerbuffer = Crypto().decrypt_data(self.sdKey, self.sdIv, headerbuffer, True)

        self.hdr = self.SavegameHeader().unpack(headerbuffer[:0x20])

        self.bnr = self.SavegameBanner().unpack(headerbuffer[0x20:])

        if self.bnr.magic != b'WIBN':
            raise Exception('Wrong magic, should be WIBN')

        if self.hdr.md5hash != Crypto().create_md5hash(headerbuffer.replace(self.hdr.md5hash, self.md5Blanker)):
            raise Exception("MD5 Sum mismatch!")

        if self.hdr.bannerSize != 0x72A0:
            self.iconCount += 7

        bkhdrbuffer = self.file.read(0x80)
        self.bkHdr = self.BackupHeader().unpack(bkhdrbuffer)

        if self.bkHdr.magic != b'Bk' or self.bkHdr.hdrSize != 0x70:
            raise Exception('Bk header error')

        self.fileStartOffset = self.file.tell()

    def extract_files(self):
        """Extracts all files from a Savegame (minus icon and banner)."""
        try:
            os.mkdir(os.path.join(os.path.dirname(self.f), self.bkHdr.gameId.decode()))
        except:
            pass

        os.chdir(os.path.join(os.path.dirname(self.f), self.bkHdr.gameId.decode()))

        self.file.seek(self.fileStartOffset)

        for i in range(self.bkHdr.filesCount):
            filehdr = self.file.read(0x80)
            file_iv = filehdr[0x050:0x050 + 16]
            filehdr = self.FileHeader().unpack(filehdr)

            if filehdr.magic != b"\x03\xad\xf1\x7e":
                raise Exception('Wrong file magic')

            filehdr.size = align(filehdr.size, 64)

            name = b""
            for char in [filehdr.namedata[x:x + 1] for x in range(len(filehdr.namedata))]:
                if char != b"\x00":
                    name += char
                else:
                    break

            if filehdr.type == 1:
                print('Extracted {0} ({1} bytes)'.format(name.decode(), filehdr.size))

                filebuffer = self.file.read(filehdr.size)
                filebuffer = Crypto().decrypt_data(self.sdKey, file_iv, filebuffer, True)
                try:
                    open(name.decode(), 'w+b').write(filebuffer)
                except:
                    os.chdir("..")
                    raise Exception('Cannot write the output')
            elif filehdr.type == 2:
                print('Extracted folder {0}'.format(name.decode()))
                try:
                    os.mkdir(name.decode())
                except:
                    os.chdir("..")
                    raise Exception('Cannot create folder')

            print('Attribute {0} Permission {1}'.format(filehdr.attribute, filehdr.permissions))
            print('File IV : {0}'.format(dump(file_iv)))

        os.chdir('..')

    def extract_banner(self):
        """Extracts all files from a Savegame (minus icon and banner)."""
        try:
            os.mkdir(os.path.join(os.path.dirname(self.f), self.bkHdr.gameId.decode()))
        except:
            pass

        os.chdir(os.path.join(os.path.dirname(self.f), self.bkHdr.gameId.decode()))
        # Image.fromstring("RGBA", (192, 64), TPL('').RGB5A3((192, 64), self.bnr.banner)).save('banner', 'png')
        os.chdir("..")
        raise NotImplementedError()

    def extract_icon(self, index=0):
        """Extracts an icon from the save.

        Args:
            index (int): Which icon to extract (Default: 0)
        """
        raise NotImplementedError()

    def erase_wii_mac(self):
        """Overrides the Wii's MAC address with null bytes."""
        self.file.seek(0xF128)
        print(self.file.write(b"\x00" * 6))

    def get_icons_count(self):
        """Returns the total number of icons in the save."""
        return self.iconCount

    def get_files_count(self):
        """Returns the total number of files in the save."""
        return self.bkHdr.filesCount

    def get_save_string(self, string):
        """Returns varies strings from the save

        Args:
            string (str): "id" for ID4, "title" for game title,
            "subtitle" for the game's subtitle and "mac" for the Wii's MAC address.
        """
        if string == 'id':
            return self.bkHdr.gameId
        elif string == 'title':
            return self.bnr.gameTitle
        elif string == 'subtitle':
            return self.bnr.gameSubTitle
        elif string == 'mac':
            return "%02x:%02x:%02x:%02x:%02x:%02x" % (self.bkHdr.wiiMacAddr[0], self.bkHdr.wiiMacAddr[1],
                                                      self.bkHdr.wiiMacAddr[2], self.bkHdr.wiiMacAddr[3],
                                                      self.bkHdr.wiiMacAddr[4], self.bkHdr.wiiMacAddr[5])

    def __repr__(self):
        return "Wii Savegame for {0}".format(self.bkHdr.gameId.decode())

    def __str__(self):
        game_id = self.bkHdr.gameId.decode()
        blocks = int(round(self.bkHdr.totalSize / 131072, 0))

        output = "Wii Savegame:\n"

        output += " Main header:\n"
        output += "  Savegame ID: {0}\n".format(self.hdr.savegameId)
        output += "  Banner size: {0} bytes\n".format(self.hdr.bannerSize)
        output += "  Permissions: {0}\n".format(self.hdr.permissions)
        output += "  MD5 hash: {0}\n\n".format(hexlify(self.hdr.md5hash).decode())

        output += " Banner header:\n"
        output += "  Flags: {0} {1}\n".format(self.bnr.flags, "(can not be copied)" if self.bnr.flags == 1 else "")
        output += "  Animation Speed: {0}\n".format(self.bnr.animSpeed)
        output += "  Game Title: {0}\n".format(self.bnr.gameTitle.replace(b"\x00", b"").decode("latin-1"))
        output += "  Subtitle: {0}\n".format(self.bnr.gameSubTitle.replace(b"\x00", b"").decode("latin-1"))
        output += "  Icons found: {0}\n\n".format(self.iconCount)

        output += " Backup header:\n"
        output += "  Game ID: {0}\n".format(game_id)
        if game_id[3] == "P":
            output += "  Region: PAL\n"
        elif game_id[3] == "E":
            output += "  Region: USA\n"
        elif game_id[3] == "J":
            output += "  Region: JPN\n"
        elif game_id[3] == "K":
            output += "  Region: KOR\n"
        output += "  Wii ID: {0}\n".format(self.bkHdr.NGid)
        output += "  Wii MAC address %02x:%02x:%02x:%02x:%02x:%02x\n" % (
            self.bkHdr.wiiMacAddr[0], self.bkHdr.wiiMacAddr[1], self.bkHdr.wiiMacAddr[2], self.bkHdr.wiiMacAddr[3],
            self.bkHdr.wiiMacAddr[4], self.bkHdr.wiiMacAddr[5])
        output += "  Files found: {0}\n".format(self.bkHdr.filesCount)
        output += "  Size of files: {0} bytes\n".format(self.bkHdr.filesSize)
        output += "  Save size: {0} bytes ({1} blocks)\n".format(self.bkHdr.totalSize, blocks)

        return output


class LocDat:
    """Represents the loc.dat used by the SD Card Menu which holds the position of all titles.
       Reference: http://wiibrew.org/wiki/Loc.dat

    Args:
        f (str): Path to loc.dat
    """

    class LocHeader(Struct):
        def __format__(self, func=None):
            self.magic = Struct.string(4)
            self.md5 = Struct.string(16)

    def __init__(self, f):
        self.sdKey = b"\xAB\x01\xB9\xD8\xE1\x62\x2B\x08\xAF\xBA\xD8\x4D\xBF\xC2\xA5\x5D"
        self.sdIv = b"\x21\x67\x12\xE6\xAA\x1F\x68\x9F\x95\xC5\xA2\x23\x24\xDC\x6A\x98"
        self.md5Blanker = b"\x0E\x65\x37\x81\x99\xBE\x45\x17\xAB\x06\xEC\x22\x45\x1A\x57\x93"

        self.titles = []
        self.usedBlocks = 0
        self.freeBlocks = 0

        try:
            self.file = open(f, 'r+b')
        except FileNotFoundError:
            raise FileNotFoundError('File not found')

        plainbuffer = Crypto().decrypt_data(self.sdKey, self.sdIv, self.file.read(), False)
        self.header = self.LocHeader().unpack(plainbuffer[:0x14])
        if self.header.magic != b"sdal":
            raise Exception("Magic word is wrong, should be 'sdal'")

        for slot in range(240):
            self.titles.append(plainbuffer[0x14 + slot * 4:0x14 + (slot + 1) * 4])
            if self.titles[slot] == b"\x00\x00\x00\x00":
                self.freeBlocks += 1
        self.usedBlocks = 240 - self.freeBlocks

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
            page (int): Page number (1-20)
        """
        if not 1 <= col <= 4 or not 1 <= row <= 3 or not 1 <= page <= 20:
            raise ValueError("Out of bounds")
        if self.titles[((col - 1) + ((row - 1) * 4) + ((page - 1) * 12))] == b"\x00\x00\x00\x00":
            return True
        return False

    def is_title_in_list(self, title):
        """Returns the index of title in self.titles or -1 if it doesn't exist."""
        try:
            return self.titles.index(title.upper().encode())
        except ValueError:
            return -1

    def get_titles_from_page(self, page):
        """Returns all titles from a page"""
        if not 1 <= page <= 20:
            raise ValueError("Out of bounds")

        return self.titles[12 * (page - 1):12 * page]

    def get_title(self, col, row, page):
        """Returns the title in col in row on page."""
        if not 1 <= col <= 4 or not 1 <= row <= 3 or not 1 <= page <= 20:
            raise ValueError("Out of bounds")

        return self.titles[((col - 1) + ((row - 1) * 4) + ((page - 1) * 12))]

    def set_title(self, col, row, page, element):
        """Sets element to col -> row on page.

        Args:
            col (int): Column number (1-4)
            row (int): Row number (1-3)
            page (int): Page number (1-20)
            element (Union[str, bytes]): ID4 of the channel
        """
        if not 1 <= col <= 4 or not 1 <= row <= 3 or not 1 <= page <= 20:
            raise ValueError("Out of bounds")

        if len(element) > 4:
            raise ValueError("ID4 too long")

        if isinstance(element, bytes):
            element = element.upper()
        else:
            element = element.upper().encode()
        self.titles[((col - 1) + ((row - 1) * 4) + ((page - 1) * 12))] = element

        titles = b""

        titles += self.header.magic
        titles += self.md5Blanker

        for x in range(240):
            titles += self.titles[x]

        titles += b"\x00" * 12

        newfile = self.header.magic + Crypto().create_md5hash(titles) + titles[0x14:]

        self.file.seek(0)
        self.file.write(Crypto().encrypt_data(self.sdKey, self.sdIv, newfile))

    def delete_title(self, col, row, page):
        """Deletes title from column -> row on page.

        NOTE: The Wii will add the title again, if it's present on the SD card!
        """
        self.set_title(col, row, page, b"\x00\x00\x00\x00")

    def __repr__(self):
        return "Wii LocDat: {0} slots used out of 240 ({1} free)".format(self.usedBlocks, self.freeBlocks)

    def __str__(self):
        output = "LocDat:\n"
        output += "  Used {0} slots out of 240 ({1} free)\n\n".format(self.usedBlocks, self.freeBlocks)

        for page in range(20):
            output += "  Page {0}:\n    ".format(page + 1)
            for row in range(3):
                for slot in range(4):
                    curtitle = self.titles[(slot + (row * 4) + (page * 12))]
                    if curtitle == b"\x00\x00\x00\x00":
                        output += "{0:8}".format("Empty")
                    else:
                        output += "{0:8}".format(curtitle.decode())
                if row == 2:
                    output += "\n\n"
                else:
                    output += "\n    "
        return output
