import os
import pathlib
import pefile
import re
from datetime import datetime
import math
from capstone import *

# 1. File Metadata
def get_file_metadata(file_path):
    try:
        file_info = pathlib.Path(file_path)

        # Get file size
        file_size = file_info.stat().st_size

        # Get file creation and modification times
        creation_time = datetime.fromtimestamp(file_info.stat().st_ctime)
        modification_time = datetime.fromtimestamp(file_info.stat().st_mtime)

        # Get file type (extension)
        file_type = file_info.suffix

        return {
            "File Size": f"{file_size} bytes",
            "File Type": file_type,
            "Creation Time": creation_time.strftime("%Y-%m-%d %H:%M:%S"),
            "Last Modified Time": modification_time.strftime("%Y-%m-%d %H:%M:%S")
        }

    except Exception as e:
        return f"Error: {e}"


# 2. Byte sequence
def read_file_bytes(file_path):
    try:
        # Open the file in binary read mode
        with open(file_path, 'rb') as file:
            byte_sequence = file.read()
            return byte_sequence
    except Exception as e:
        return f"Error: {e}"

# 3. API Calls/ System Calls
def get_imported_api_calls(file_path):
    try:
        pe = pefile.PE(file_path)

        api_calls = []
        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                for imp in entry.imports:
                    api_calls.append(imp.name.decode())

        return api_calls
    except Exception as e:
        return f"Error: {e}"

# 4. String Features
def extract_strings(file_path, min_length=4):
    """
    Extracts printable strings from a binary file.

    :param file_path: Path to the binary file
    :param min_length: Minimum string length to consider (default is 4)
    :return: A list of extracted strings
    """
    try:
        with open(file_path, 'rb') as file:
            content = file.read()
            # Regular expression to find printable strings
            strings = re.findall(b'[ -~]{' + str(min_length).encode() + b',}', content)
            # Decode bytes to strings
            return [s.decode() for s in strings]
    except Exception as e:
        return f"Error: {e}"

# 5. File entropy
def calculate_entropy(file_path):
    """
    Calculate the Shannon entropy of a file.

    :param file_path: Path to the file.
    :return: The calculated entropy.
    """
    try:
        # Read the entire file into a byte array
        with open(file_path, 'rb') as file:
            byteArr = list(file.read())

        fileSize = len(byteArr)
        # Create a frequency array
        freqList = [0] * 256

        # Count the occurrences of each byte
        for byte in byteArr:
            freqList[byte] += 1

        # Calculate the entropy
        entropy = 0
        for freq in freqList:
            if freq > 0:
                freq = float(freq) / fileSize
                entropy += - freq * math.log(freq, 2)

        return entropy
    except Exception as e:
        return f"Error: {e}"

# 6. Disassemble file
def disassemble(file_path):
    try:
        # Load the executable
        pe = pefile.PE(file_path)

        # Get the .text section (commonly contains executable code)
        for section in pe.sections:
            if b'.text' in section.Name:
                text_section = section
                break
        else:
            raise ValueError("No .text section found in the executable")

        # Disassemble the machine code in the .text section
        md = Cs(CS_ARCH_X86, CS_MODE_32)  # For x86 32-bit, change as needed
        for i in md.disasm(text_section.get_data(), text_section.VirtualAddress):
            print(f"0x{i.address:x}: {i.mnemonic} {i.op_str}")

    except Exception as e:
        print(f"Error: {e}")

file_path = "C:\\Users\\rober\\OneDrive\\Desktop\\sxstrace.exe"  # Replace with your file path


# 1. File Metadata
metadata = get_file_metadata(file_path)
#print(metadata)


# 2. Byte sequence
bytes_data = read_file_bytes(file_path)
# To display a portion of the byte sequence, for example first 100 bytes
#print(bytes_data)

# 3. API Calls/ System Calls

api_calls = get_imported_api_calls(file_path)
#print(api_calls)


# 4. String Features

strings = extract_strings(file_path)
#print(strings)


# 5. File Entropy

entropy = calculate_entropy(file_path)
#print(f"Entropy of the file: {entropy}")


# 6. Disasseble file
#disassemble(file_path)

