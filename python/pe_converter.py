import pefile
import sys

def generate_header(binary_filename, output_filename):
    pe_file = pefile.PE(binary_filename)
    offset = pe_file.sections[0].PointerToRawData
    size = pe_file.sections[0].SizeOfRawData

    binary_file = open(binary_filename, "rb")
    binary_file.seek(offset)
    binary = binary_file.read(size)

    i = 0
    for b in reversed(binary):
        i += 1
        if b != 0:
            break
    size -= i
    binary = binary[0:size]


    header_file = open(output_filename, "w")
    header_file.write("uint32_t payload_zx = " + str(size) + ";\n")
    header_file.write("uint32_t payload_EP_offset = " + hex(pe_file.OPTIONAL_HEADER.AddressOfEntryPoint - pe_file.sections[0].VirtualAddress) + ";\n")
    header_file.write("unsigned char rawData[] = {")

    for i, b in enumerate(binary):
        if i != 0:
            header_file.write(", ")
        header_file.write(hex(b))
    header_file.write("};\n")

if __name__ == "__main__":

    bin_filename = r"../bin/shell_generator.exe"
    output_filename = r"../bin/shellcode.h";

    if len(sys.argv) == 2:
        bin_filename = sys.argv[1]
    elif len(sys.argv) == 3:
        output_filename = sys.argv[2]
        
    generate_header(bin_filename, output_filename)
