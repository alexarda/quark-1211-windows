import os

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