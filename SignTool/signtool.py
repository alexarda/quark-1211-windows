import os
import struct
import subprocess
import ConfigParser
import hashlib

# ---- CONFIGURATION ----
SIGN_EXE = "signtool.exe"
KEY_FILE = "assets/private.pem"
LAYOUT_FILE = "assets/layout.conf"
PDAT_PATH = "assets/pdat.bin"
SIGNED_DIR = "signed_output"
UNSIGNED_DIR = r"..\Build\QuarkPlatform\DEBUG_VS2008x86xASL\FV\FlashModules"
OUTPUT_IMAGE = "firmware.bin"
FINAL_IMAGE = "withPDAT.bin"
LOG_FILE = "firmware.log"
IMAGE_SIZE = 8 * 1024 * 1024
FILL_BYTE = 0xC0
MFH_OFFSET = 0x708000
PDAT_OFFSET = 0x710000

MFH_ENTRY_STRUCT = '<IIII'
MFH_ITEM_TYPE = {
    'host_fw_stage1_signed': 0x00000001,
    'host_fw_stage2_signed': 0x00000004,
    'flash_image_version': 0x00000019,
}

if not os.path.exists(SIGNED_DIR):
    os.makedirs(SIGNED_DIR)

# ---- LOAD CONFIG ----
config = ConfigParser.ConfigParser()
config.optionxform = str
config.read(LAYOUT_FILE)

log_entries = []
sections = []

# ---- SIGNING ----
print("[STEP] Signing assets...")
for section in config.sections():
    try:
        sign = config.get(section, "sign").lower()
    except:
        sign = ""

    if sign != "yes":
        continue

    try:
        input_file = config.get(section, "item_file")
    except:
        input_file = None

    if not input_file or not os.path.isfile(input_file):
        warn = "[WARNING] Skipping {}: invalid or missing file: {}".format(section, input_file)
        print(warn)
        log_entries.append(warn)
        continue

    input_filename = os.path.basename(input_file)
    output_file = os.path.join(SIGNED_DIR, input_filename + ".signed")
    abs_output_file = os.path.abspath(output_file)
    abs_input_file = os.path.abspath(input_file)

    cmd = [
        SIGN_EXE,
        "-i", abs_input_file,
        "-k", KEY_FILE,
        "-s", "1",
        "-x", config.get(section, "svn_index") if config.has_option(section, "svn_index") else "0",
        "-o", abs_output_file
    ]

    print("[INFO] CMD: {}".format(" ".join(cmd)))
    result = subprocess.call(cmd)
    if result != 0:
        err = "[ERROR] Failed to sign {}".format(abs_input_file)
        print(err)
        log_entries.append(err)
    else:
        ok = "[OK] Signed: {}".format(abs_output_file)
        print(ok)
        log_entries.append(ok)
        config.set(section, "item_file", abs_output_file)

# ---- BUILD MFH STRUCT ----
class Section(object):
    def __init__(self, name, address, stype, item_file=None, boot_index=None, signed=False):
        self.name = name
        self.address = address
        self.stype = stype
        self.item_file = item_file
        self.boot_index = boot_index
        self.signed = signed
        self.size = 0

    def final_path(self):
        if os.path.isabs(self.item_file):
            path = self.item_file
        else:
            path = os.path.join(SIGNED_DIR if self.signed else UNSIGNED_DIR, os.path.basename(self.item_file))
        if not os.path.exists(path):
            raise IOError("[ERROR] Missing: {}".format(path))
        return path

    def mfh_entry(self):
        stype_key = self.stype.lower().split('mfh.')[1]
        mfh_type = MFH_ITEM_TYPE[stype_key]
        return struct.pack(MFH_ENTRY_STRUCT, mfh_type, self.address, self.size, 0xf3f3f3f3)

def parse_layout():
    layout = []
    mfh_version = 0
    mfh_flags = 0
    image_version = 0

    for section in config.sections():
        if not config.has_option(section, 'type'):
            continue
        stype = config.get(section, 'type').strip().lower()
        if stype == 'mfh':
            mfh_version = int(config.get(section, 'version'), 0)
            mfh_flags = int(config.get(section, 'flags'), 0)
        elif config.has_option(section, 'meta') and config.get(section, 'meta') == 'version':
            image_version = int(config.get(section, 'value'), 0)
        elif stype.startswith('mfh.') and not stype.startswith('mfh.version'):
            if not config.has_option(section, 'address') or not config.has_option(section, 'item_file'):
                continue
            address = int(config.get(section, 'address'), 0)
            item_file = config.get(section, 'item_file')
            signed = config.get(section, 'sign', 'no').lower() == 'yes'
            boot_index = int(config.get(section, 'boot_index')) if config.has_option(section, 'boot_index') else None
            sec = Section(section, address, stype, item_file, boot_index, signed)
            layout.append(sec)
    return layout, mfh_version, mfh_flags, image_version

def generate_mfh(layout, mfh_version, mfh_flags, image_version):
    mfh_body = ''
    mfh_count = 0
    for sec in layout:
        filepath = sec.final_path()
        sec.size = os.path.getsize(filepath)

    boot_items = [s for s in layout if s.boot_index is not None]
    boot_items.sort(key=lambda x: x.boot_index)
    for item in boot_items:
        mfh_body += struct.pack('<I', layout.index(item))
    for item in layout:
        mfh_body += item.mfh_entry()
        mfh_count += 1
    if image_version > 0:
        mfh_body += struct.pack(MFH_ENTRY_STRUCT, MFH_ITEM_TYPE['flash_image_version'], 0x0, 0x0, image_version)
        mfh_count += 1

    mfh_head = struct.pack('<IIIIII',
        0x5F4D4648,
        mfh_version,
        mfh_flags,
        0x00000000,
        mfh_count,
        len(boot_items)
    )

    mfh_struct = mfh_head + mfh_body
    if len(mfh_struct) > 512:
        raise Exception("MFH too large")
    mfh_struct += chr(0xF3) * (512 - len(mfh_struct))
    return mfh_struct

# ---- BUILD IMAGE ----
print("[STEP] Assembling image...")
sections = []
for section in config.sections():
    if config.has_option(section, "address") and config.has_option(section, "item_file"):
        addr = int(config.get(section, "address"), 0)
        path = config.get(section, "item_file")
        sections.append((addr, path, section))

sections.sort()
image = bytearray([FILL_BYTE] * IMAGE_SIZE)

for addr, path, name in sections:
    offset = addr - 0xFFFFFFFF + IMAGE_SIZE - 1
    if not os.path.isfile(path):
        print("[WARNING] Skipping {}: file not found -> {}".format(name, path))
        continue
    with open(path, "rb") as f:
        data = f.read()
    image[offset:offset + len(data)] = data
    print("[OK] Placed {} at 0x{:X}, size {}".format(name, offset, len(data)))

# ---- INSERT MFH ----
layout, mver, mflag, imgver = parse_layout()
mfh = generate_mfh(layout, mver, mflag, imgver)
image[MFH_OFFSET:MFH_OFFSET+512] = mfh
print("[OK] Inserted MFH at 0x{:X}".format(MFH_OFFSET))

# ---- INSERT PDAT ----
if os.path.isfile(PDAT_PATH):
    with open(PDAT_PATH, "rb") as f:
        pdat = f.read()
    image[PDAT_OFFSET:PDAT_OFFSET + len(pdat)] = pdat
    print("[OK] Inserted PDAT at 0x{:X}".format(PDAT_OFFSET))

# ---- WRITE FINAL IMAGE ----
with open(FINAL_IMAGE, "wb") as f:
    f.write(image)
print("[DONE] Final image: {}".format(FINAL_IMAGE))

# ---- LOG SHA256 ----
sha = hashlib.sha256(image).hexdigest()
print("[CHECKSUM] SHA-256: {}".format(sha))
