# -*-coding:utf-8-*-
import os
import sys
import json
import struct
import shutil

'''
解包、重打包萤石云(ezviz)摄像头升级固件脚本

'''


def sar(n, pos):
    tmp = bin(n)[2:]
    while len(tmp) < 8: tmp = '0%s' %(tmp)
    b = tmp[0]
    tmp = bin(n >> pos)[2:]
    while len(tmp) < 8: tmp = '%s%s' %(b, tmp)
    return int(tmp, 2)

def xor_header(buf):
    length = len(buf)
    result = []
    if length > 0:
        key = '\xBA\xCD\xBC\xFE\xD6\xCA\xDD\xD3\xBA\xB9\xA3\xAB\xBF\xCB\xB5\xBE'
        for i in range(length):
            result.append(chr(ord(buf[i]) ^ ord(key[(i + sar(i, 4)) & 15])))
    return "".join(result)

'''
header长度一般为0x98，其格式（每4字节一项）：
    magic number : 'SWKH'
    header checksum
    header length
    file number
    language : 1 -> EN/ML, 2 -> CN
    device class
    OEM code
    firmware version
    feature
    ......
    file part:
        filename : length 0x20
        file offset
        file size
        file checksum
'''
def parse_header(header, is_decoded = False):
    if is_decoded:
        decoded_header = header
        raw_header = xor_header(decoded_header)
    else:
        raw_header = header
        decoded_header = xor_header(raw_header)

    magic_number = struct.unpack("<L", decoded_header[0:4])[0]
    header_checksum = struct.unpack("<L", decoded_header[4:8])[0]
    header_length = struct.unpack("<L", decoded_header[8:12])[0]
    file_number = struct.unpack("<L", decoded_header[12:16])[0]
    language = struct.unpack("<L", decoded_header[16:20])[0]
    device_class = struct.unpack("<L", decoded_header[20:24])[0]
    oem_code = struct.unpack("<L", decoded_header[24:28])[0]
    firmware_version = struct.unpack("<L", decoded_header[28:32])[0]
    feature = struct.unpack("<L", decoded_header[32:36])[0]
    

    fileinfo_length = (header_length - 64) // file_number
    
    file_items = []
    for i in xrange(64, header_length, fileinfo_length):
        file_items.append(decoded_header[i : i+fileinfo_length])
    
    file_infos = []
    for item in file_items:
        filename = item[:32].rstrip('\x00').decode('utf-8')
        file_offset = struct.unpack("<L", item[32:36])[0]
        file_size = struct.unpack("<L", item[36:40])[0]
        file_checksum = struct.unpack("<L", item[40:44])[0]
        file_info = {
            "filename" : filename,
            "file_offset" : file_offset,
            "file_size" : file_size,
            "file_checksum" : file_checksum
        }
        file_infos.append(file_info)
    
    header_info = {
        "raw_header" : raw_header,
        "decoded_header" : decoded_header,

        "magic_number" : magic_number,
        "header_checksum" : header_checksum,
        "header_length" : header_length,
        "file_number" : file_number,
        "language" : language,
        "device_class" : device_class,
        "oem_code" : oem_code,
        "firmware_version" : firmware_version,
        "feature" : feature,
        "file_infos" : file_infos
    }
    
    return header_info

def hexdump(src, length=16):
    FILTER = ''.join([(len(repr(chr(x))) == 3) and chr(x) or '.' for x in range(256)])
    lines = []
    for c in xrange(0, len(src), length):
        chars = src[c:c+length]
        hex = ' '.join(["%02x" % ord(x) for x in chars])
        printable = ''.join(["%s" % ((ord(x) <= 127 and FILTER[ord(x)]) or '.') for x in chars])
        lines.append("%04x  %-*s  %s\n" % (c, length*3, hex, printable))
    return ''.join(lines)

def print_firmware(firmware_path):
    f_firmware = open(firmware_path, 'rb')
    pre_raw_header = f_firmware.read(64)
    pre_decoded_header = xor_header(pre_raw_header)
    header_length = struct.unpack("<L", pre_decoded_header[8:12])[0]
    
    f_firmware.seek(0)
    raw_header = f_firmware.read(header_length)
    header_info = parse_header(raw_header)

    print("raw header:")
    print(hexdump(header_info["raw_header"]))
    print("decoded header:")
    print(hexdump(header_info["decoded_header"]))

    if header_info["language"] == 1:
        language_name = "EN/ML"
    elif header_info["language"] == 2:
        language_name = "CN"
    else:
        language_name = "UNKNOWN"
    print("magic number     : 0x%08x" % header_info["magic_number"])
    print("header checksum  : 0x%08x" % header_info["header_checksum"])
    print("header length    : 0x%08x" % header_info["header_length"])
    print("file number      : 0x%08x" % header_info["file_number"])
    print("language         : 0x%08x" % header_info["language"] + " (%s)" % language_name)
    print("device class     : 0x%08x" % header_info["device_class"])
    print("oem code         : 0x%08x" % header_info["oem_code"])
    print("firmware version : 0x%08x" % header_info["firmware_version"])
    print("feature          : 0x%08x" % header_info["feature"])
    print("\nfile info:")
    for file_info in header_info["file_infos"]:
        print("\tfilename         : %s" % file_info["filename"])
        print("\tfile offset      : 0x%08x" % file_info["file_offset"])
        print("\tfile size        : 0x%08x" % file_info["file_size"])
        print("\tfile checksum    : 0x%08x" % file_info["file_checksum"])
        print("\n")


def unpack_firmware(firmware_path):
    f_firmware = open(firmware_path, 'rb')
    pre_raw_header = f_firmware.read(64)
    pre_decoded_header = xor_header(pre_raw_header)
    header_length = struct.unpack("<L", pre_decoded_header[8:12])[0]
    
    f_firmware.seek(0)
    raw_header = f_firmware.read(header_length)
    header_info = parse_header(raw_header)

    if not os.path.exists(firmware_path + '_unpacked'):
        os.mkdir(firmware_path + '_unpacked')
    os.chdir(firmware_path + '_unpacked')

    with open('header', 'wb') as f:
        f.write(header_info["decoded_header"])

    for file_info in header_info["file_infos"]:
        with open(file_info["filename"], "wb") as f:
            f_firmware.seek(file_info["file_offset"])
            f.write(f_firmware.read(file_info["file_size"]))

    print(firmware_path + ' has unpacked.')


def calc_checksum(data):
    checksum = 0
    for i in data:
        checksum += ord(i)
    return checksum

def repack_firmware(firmware_dir):
    os.chdir(firmware_dir)
    decoded_header = open('header', 'rb').read()
    header_info = parse_header(decoded_header, is_decoded=True)

    file_offset = len(decoded_header)
    decoded_header = decoded_header[:64]

    # change files info
    for file_info in header_info["file_infos"]:
        filename = file_info["filename"]
        filedata = open(filename, 'rb').read()
        filename = filename.encode('utf-8').ljust (32, b'\x00')
        file_size = len(filedata)
        file_checksum = calc_checksum(filedata)
        
        decoded_file = filename + struct.pack('<L', file_offset) + struct.pack('<L', file_size) + struct.pack('<L', file_checksum)
        decoded_header += decoded_file
        file_offset += file_size
    
    # change header info
    decoded_header = list(decoded_header)
    decoded_header[4:8] = struct.pack('<L', calc_checksum("".join(decoded_header[12:]))) # from offset 12 to headerlen
    decoded_header = "".join(decoded_header)

    raw_header = xor_header(decoded_header)

    # pack
    new_firmware_path = firmware_dir.rstrip('/').rstrip('\\').split('/')[-1].split('\\')[-1].rsplit('_unpacked', 1)[0]
    new_firmware_path = "new_" + new_firmware_path
    f_new_firmware = open(new_firmware_path, 'wb')

    f_new_firmware.write(raw_header)

    for file_info in header_info["file_infos"]:
        filename = file_info["filename"]
        shutil.copyfileobj(open(filename, 'rb'), f_new_firmware)

    f_new_firmware.close()
    print("%s has created." % new_firmware_path)


USAGE = '''
Unpack/Repack Hikvision IPC firmware
Usage:
    python %(prog)s /path/to/target_digicap.dav
    python %(prog)s unpack /path/to/target_digicap.dav
    python %(prog)s repack /path/to/unpacked_firmware_folder
''' % {"prog": sys.argv[0]}

def main():
    if len(sys.argv) == 2:
        print_firmware(sys.argv[1])
    elif len(sys.argv) > 2:
        if sys.argv[1] == "unpack":
            unpack_firmware(sys.argv[2])
        elif sys.argv[1] == "repack":
            repack_firmware(sys.argv[2])
        else:
            print(USAGE)
    else:
        print(USAGE)

if __name__ == "__main__":
    main()
