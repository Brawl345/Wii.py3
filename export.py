#!/usr/bin/env python3
from Struct import Struct

from common import *


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
            raise ValueError("Magic word is wrong, should be 'sdal'")

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
        return "Wii LocDat: {0} blocks used out of 240 ({1} free)".format(self.usedBlocks, self.freeBlocks)

    def __str__(self):
        output = "LocDat:\n"
        output += "  Used {0} blocks out of 240 ({1} free)\n\n".format(self.usedBlocks, self.freeBlocks)

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
