#!/usr/bin/env python

# jffs2.py is free software: you can
# redistribute it and/or modify it under the terms of the GNU General Public
# License as published by the Free Software Foundation, version 2.

import struct
import sys
import mmap
import os
import errno
import zlib
import logging


from collections import defaultdict

logger = logging.getLogger(__name__)

try:
    import lzo
except ImportError:
    lzo = None


def PAD(x):
    if x % 4:
        x += 4-(x%4)
    return x

JFFS2_NODETYPE_DIRENT = 0xE001
JFFS2_NODETYPE_INODE = 0xE002

DT_DIR = 4
DT_REG = 8

JFFS2_COMPR_NONE = 0x00
JFFS2_COMPR_ZERO = 0x01
JFFS2_COMPR_RTIME = 0x02
JFFS2_COMPR_RUBINMIPS = 0x03
JFFS2_COMPR_COPY = 0x04
JFFS2_COMPR_DYNRUBIN = 0x05
JFFS2_COMPR_ZLIB = 0x06
JFFS2_COMPR_LZO = 0x07


def mkdir_p(path):
    try:
        os.makedirs(path)
    except OSError as exc:
        if exc.errno == errno.EEXIST:
            pass
        else:
            raise


def rtime_decompress(src, dstlen):
    pos = 0
    positions = [0] * 256

    out = b""
    while len(out) < dstlen:
        val = src[pos:pos+1]
        pos += 1
        out += val

        repeat = ord(src[pos:pos+1])
        pos += 1
        backoffs = positions[ord(val)]

        positions[ord(val)] = len(out)
        if repeat:
            if backoffs + repeat >= len(out):
                while repeat:
                    out += out[backoffs:backoffs+1]
                    backoffs += 1
                    repeat -= 1
            else:
                out += out[backoffs:backoffs+repeat]
    return out

class JFFS2:
    def __init__(self, image):
        with open(image, 'rb') as self.fd:
            self.image = mmap.mmap(self.fd.fileno(), 0, prot=mmap.PROT_READ)
            initial, = struct.unpack('<H', self.image[0:2])
            if initial == 0x8519:
                self.endian = ">"
                logger.debug("Little endian detected")
            else:
                self.endian = "<"
                logger.debug("Big endian detected")

        self.dirents = {}
        self.inodes = defaultdict(list)

    def scan_dirent(self, mm):
        # jint32_t pino;
        # jint32_t version;
        # jint32_t ino; /* == zero for unlink */
        # jint32_t mctime;
        # uint8_t nsize;
        # uint8_t type;
        # uint8_t unused[2];
        # jint32_t node_crc;
        # jint32_t name_crc;
        # uint8_t name[0];

        if len(mm) < 28:
            return False

        pino, version, ino, mctime, nsize, ntype, unused, node_crc, name_crc = struct.unpack("%sLLLLBBHLL"%self.endian, mm[0:28])

        if 28+nsize > len(mm):
            return False

        old_dirent = self.dirents.get('ino', None)
        if old_dirent and old_dirent[1] > version:
            return True

        fname = mm[28:28+nsize].decode('utf-8', errors='replace').replace('\0','0')

        self.dirents[ino] = (pino, version, mctime, ntype, fname)
        return True

    def scan_inode(self, mm, idx):
        # jint32_t ino;        /* Inode number.  */
        # jint32_t version;    /* Version number.  */
        # jmode_t mode;       /* The file's type or mode.  */
        # jint16_t uid;        /* The file's owner.  */
        # jint16_t gid;        /* The file's group.  */
        # jint32_t isize;      /* Total resultant size of this inode (used for truncations)  */
        # jint32_t atime;      /* Last access time.  */
        # jint32_t mtime;      /* Last modification time.  */
        # jint32_t ctime;      /* Change time.  */
        # jint32_t offset;     /* Where to begin to write.  */
        # jint32_t csize;      /* (Compressed) data size */
        # jint32_t dsize;      /* Size of the node's data. (after decompression) */
        # uint8_t compr;       /* Compression algorithm used */
        # uint8_t usercompr;   /* Compression algorithm requested by the user */
        # jint16_t flags;      /* See JFFS2_INO_FLAG_* */
        # jint32_t data_crc;   /* CRC for the (compressed) data.  */
        # jint32_t node_crc;   /* CRC for the raw inode (excluding data)  */
        # uint8_t data[0];
        (ino, version, mode, uid, gid, isize, atime, mtime, ctime, offset,
         csize, dsize, compr, usercompr, flags, data_crc, node_crc
         ) = struct.unpack("%sLLLHHLLLLLLLBBHLL"%self.endian, mm[0:56])

        if csize > len(mm[56:]):
            return False

        for old_node in self.inodes[ino]:
            if old_node[0] > version and offset == old_node[3]:
                return True

        data = idx+56
        self.inodes[ino].append((version, isize, mtime, offset, csize, dsize, compr, data))
        return True

    def scan(self):
        idx = 0
        mm = self.image
        maxmm = len(self.image)

        while idx < maxmm-12:
            magic, nodetype, totlen, hdh_crc = struct.unpack("%sHHLL"%self.endian, mm[idx:idx+12])
            if magic != 0x1985:
                idx += 4
                continue

            if totlen > maxmm-idx or totlen == 0:
                break

            if nodetype == JFFS2_NODETYPE_DIRENT:
                self.scan_dirent(mm[idx+12:idx+totlen])
            elif nodetype == JFFS2_NODETYPE_INODE:
                self.scan_inode(mm[idx+12:idx+totlen], idx+12)
            else:
                logger.debug("Unknown nodetype")

            idx += PAD(totlen)

    def dump_file(self, name, node):
        logger.info("Writing file %s" % name)
        mkdir_p(os.path.dirname(name))

        with open(name, "wb") as wfd:
            inodes = self.inodes[node]
            sorted_nodes = sorted(inodes, key=lambda item: item[3])
            ts = 0
            for inode in sorted_nodes:
                (version, isize, mtime, offset, csize, dsize, compr, dataidx) = inode
                ts = mtime
                if compr == JFFS2_COMPR_NONE:
                    wfd.write(self.image[dataidx:dataidx+csize])
                elif compr == JFFS2_COMPR_ZLIB:
                    try:
                        decompr = zlib.decompress(self.image[dataidx:dataidx+csize])
                        wfd.write(decompr)
                    except zlib.error:
                        logger.critical("Failed to decompress zlib, dumping raw")
                        wfd.write(self.image[dataidx:dataidx+csize])
                elif compr == JFFS2_COMPR_RTIME:
                    try:
                        decompr = rtime_decompress(self.image[dataidx:dataidx+csize], dsize)
                        wfd.write(decompr)
                    except IndexError:
                        logger.critical("rtime failed, dumping")
                        wfd.write(self.image[dataidx:dataidx+csize])
                elif compr == JFFS2_COMPR_LZO:
                    if lzo is None:
                        logger.critical("No lzo installed!")
                    try:
                        compressed = '\xf0' + struct.pack('!L', dsize) + self.image[dataidx:dataidx+csize]
                        decompr = lzo.decompress(compressed)
                        wfd.write(decompr)
                    except lzo.error as e:
                        logger.critical("Failed to decompress lzo, dumping raw (%s)" % str(e))
                        wfd.write(self.image[dataidx:dataidx+csize])
                else:
                    logger.critical("Unknown compression %d" % compr)
        os.utime(name, (ts, ts))

    def resolve_dirent(self, node):
        current = node
        ntype = self.dirents[node][3]
        path = ""
        cnode = self.dirents[node]
        i = 32
        while i:
            if cnode[0] == 1:
                path = os.path.join(cnode[4], path)
                return path.lstrip("/").rstrip("/").strip("../"), ntype
            else:
                path = os.path.join(cnode[4], path)
                cnode = self.dirents.get(cnode[0], None)
                if cnode is None:
                    raise ValueError
                i -= 1
        raise ValueError

    def dump(self, target):
        for i in self.dirents:
            dirent = self.dirents[i]
            try:
                name, ntype = self.resolve_dirent(i)
            except ValueError:
                return 

            if ntype == DT_REG:
                self.dump_file(os.path.join(target, name), i)
            elif ntype == DT_DIR:
                mkdir_p(os.path.join(target, name))


def main():
    logging.basicConfig(format=("%(asctime)s:%(name)s:%(levelname)s:"
                                "%(message)s"),
                        level=logging.DEBUG)

    jffs = JFFS2(sys.argv[1])
    jffs.scan()
    jffs.dump(sys.argv[2])

if __name__ == '__main__':
    main()



