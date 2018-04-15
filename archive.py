#!/usr/bin/env python3
import array
import os

from Struct import Struct


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
