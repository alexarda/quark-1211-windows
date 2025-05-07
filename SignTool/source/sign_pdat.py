import ConfigParser
import os
import subprocess
import struct
import hashlib

# Configuration
SIGN_EXE = "signtool.exe"
KEY_FILE = "private.pem"
OUTPUT_DIR = "signed_output"
LAYOUT_FILE = "layout.conf"
OUTPUT_IMAGE = "firmware.bin"
LOG_FILE = "firmware.log"
IMAGE_SIZE = 8 * 1024 * 1024  # 8MB
FILL_BYTE = 0xC0  # Based on original generator.py behavior

# Ensure output directory exists
if not os.path.exists(OUTPUT_DIR):
    os.makedirs(OUTPUT_DIR)

# Read layout.conf
config = ConfigParser.ConfigParser()
config.optionxform = str
config.read(LAYOUT_FILE)

log_entries = []
sections = []

# --- Signing Phase ---
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

    try:
        svn_index = config.get(section, "svn_index")
    except:
        svn_index = "0"

    svn = "1"

    if not input_file or not os.path.isfile(input_file):
        warn = "[WARNING] Skipping {}: invalid or missing file: {}".format(section, input_file)
        print(warn)
        log_entries.append(warn)
        continue

    input_filename = os.path.basename(input_file)
    output_file = os.path.join(OUTPUT_DIR, input_filename + ".signed")
    abs_output_file = os.path.abspath(output_file)
    abs_input_file = os.path.abspath(input_file)

    cmd = [
        SIGN_EXE,
        "-i", abs_input_file,
        "-k", KEY_FILE,
        "-s", svn,
        "-x", svn_index,
        "-o", abs_output_file
    ]

    print("[INFO] CMD: {}".format(" ".join(cmd)))
    print("[INFO] Signing {} -> {}".format(abs_input_file, abs_output_file))
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

# --- Assembly Phase ---
print("[STEP] Assembling final image...")
for section in config.sections():
    try:
        addr_str = config.get(section, "address")
        file_path = config.get(section, "item_file")
        if addr_str and file_path:
            addr = int(addr_str, 16)
            sections.append((addr, file_path, section))
    except:
        continue

sections.sort()
image = bytearray([FILL_BYTE] * IMAGE_SIZE)

for idx, (addr, file_path, section) in enumerate(sections):
    offset = addr - 0xFFFFFFFF + IMAGE_SIZE - 1  # match generator.py logic
    file_path_abs = os.path.abspath(file_path)

    if not os.path.isfile(file_path_abs):
        warn = "[WARNING] Skipping {}: file not found -> {}".format(section, file_path_abs)
        print(warn)
        log_entries.append(warn)
        continue

    with open(file_path_abs, "rb") as f:
        data = f.read()

    if offset < 0 or offset + len(data) > IMAGE_SIZE:
        err = "[ERROR] Section '{}' out of bounds! Offset: 0x{:X}, size: {}, image size: {}".format(
            section, offset, len(data), IMAGE_SIZE)
        print(err)
        log_entries.append(err)
        continue

    image[offset:offset + len(data)] = data
    entry = "[OK] Placed section '{}' at offset 0x{:X}, size: {} bytes".format(section, offset, len(data))
    print(entry)
    log_entries.append(entry)

with open(OUTPUT_IMAGE, "wb") as f:
    f.write(image)

sha256_hash = hashlib.sha256(image).hexdigest()
checksum_entry = "[CHECKSUM] SHA-256: {}".format(sha256_hash)
print(checksum_entry)
log_entries.append(checksum_entry)

with open(LOG_FILE, "w") as f:
    f.write("\n".join(log_entries))

print("[DONE] Firmware image written to {}".format(OUTPUT_IMAGE))
print("[LOG] Log saved to {}".format(LOG_FILE))

def insert_pdat():
    # Define file paths
    firmware_path = "firmware.bin"
    pdat_path = "assets/pdat.bin"
    output_path = "withPDAT.bin"
    insert_offset = 0x710000

    # Read firmware
    with open(firmware_path, "rb") as fw:
        firmware_data = fw.read()

    # Read pdat
    with open(pdat_path, "rb") as pdat:
        pdat_data = pdat.read()

    # Extend firmware if needed
    if len(firmware_data) < insert_offset:
        firmware_data += b'\xFF' * (insert_offset - len(firmware_data))

    # Insert pdat at offset
    modified_data = firmware_data[:insert_offset] + pdat_data

    # If original firmware was larger than insert_offset + pdat, preserve tail
    if len(firmware_data) > insert_offset + len(pdat_data):
        modified_data += firmware_data[insert_offset + len(pdat_data):]

    # Write output
    with open(output_path, "wb") as out:
        out.write(modified_data)

    # Report result
    print("[OK] withPDAT.bin created. Size: {} bytes".format(os.path.getsize(output_path)))

# Call the function
insert_pdat()