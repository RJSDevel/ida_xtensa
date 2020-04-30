#!/usr/bin/python

import os
import struct
from idaapi import *


def accept_file(li, n):
    retval = 0
    if n == 0:
        li.seek(0)
        if li.read(1) == "e9".decode("hex"):
            retval = "ESP8266 firmware"
    return retval


def load_file(li, neflags, format):
    li.seek(0)

    # set processor type (doesn't appear to work)
    set_processor_type("xtensa", SETPROC_ALL)

    # load ROM segment
    (magic, segments, flash_mode, flash_size_freq, entrypoint) = struct.unpack('<BBBBI', li.read(8))

    print "Reading ROM boot firmware"
    print "Magic: %x" % magic
    print "Segments: %x" % segments
    print "Entry point: %x" % entrypoint
    print "\n"

    boot_sections_address = []
    for k in xrange(segments):
        (seg_addr, seg_size) = struct.unpack("<II", li.read(8))
        file_offset = li.tell()

        li.file2base(file_offset, seg_addr, seg_addr + seg_size, True)
        add_segm(k, seg_addr, seg_addr + seg_size, ".boot_rom_%d" % k, "CODE")

        print "ROM address: %x" % seg_addr
        print "ROM size: %x" % seg_size
        print "\n"

        boot_sections_address.append(seg_addr)

        li.seek(file_offset + seg_size, 0)

    idaapi.add_entry(entrypoint, entrypoint, "rom_entry", 1)

    li.seek(li.tell() - segments * 4, 0)

    print "Reading user firmware"

    (magic, segments, flash_mode, flash_size_freq, entrypoint) = struct.unpack('<BBBBI', li.read(8))
    print "Magic: %x" % magic
    print "Segments: %x" % segments
    print "Entry point: %x" % entrypoint
    print "\n"

    for k in xrange(segments):
        (seg_addr, seg_size) = struct.unpack("<II", li.read(8))

        for bsa in boot_sections_address:
            if seg_addr + seg_size > bsa:
                seg_size = bsa - seg_addr
                break

        if seg_addr == 0x40100000:
            seg_name = ".user_rom"
            seg_type = "CODE"
        elif seg_addr == 0x3FFE8000:
            seg_name = ".user_rom_data"
            seg_type = "DATA"
        elif seg_addr == 0x3FFFFFFF:
            seg_name = ".data_seg_%d" % k
            seg_type = "DATA"
        else:
            seg_name = ".unknown_seg_%d" % k
            seg_type = "CODE"

        print "Seg name: %s" % seg_name
        print "Seg type: %s" % seg_type
        print "Seg address: %x" % seg_addr
        print "Seg size: %x" % seg_size
        print "\n"

        file_offset = li.tell()
        li.file2base(file_offset, seg_addr, seg_addr + seg_size, True)
        add_segm(k, seg_addr, seg_addr + seg_size, seg_name, seg_type)

        li.seek(file_offset + seg_size, 0)

    idaapi.add_entry(entrypoint, entrypoint, "user_entry", 1)

    return 1
