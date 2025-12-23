import struct
import sys

def parse_pe_header(filepath):
    try:
        #Open file in Read Binary (rb) mode
        with open(filepath, 'rb') as f:

            #Parse DOS header
            #Focus on the first 64 bytes
            #And focus on 2 things
            #The first 2 bytes (Magic: 'MZ')
            #The last 4 bytes at offset 0x3C (e-lfanew: Pointer to PE Header)

            print(f"[*] Analyzing: {filepath}")

            #Read first 2 bytes to check for 'MZ'
            e_magic = f.read(2).decode('utf-8', errors='ignore')

            if e_magic != 'MZ':
                print("[!] Error: Not a valid PE file (Missing MZ magic).")
                return
            
            #Seek to offet 0x3C (60) to find e_lfanew
            f.seek(0x3C)
            #Unpack 4 bytes as a Little-Endian Integer (<I)
            e_lfanew = struct.unpack('<I', f.read(4))[0]

            print(f"[+] DOS Header found.")
            print(f"    -> Magic: {e_magic}")
            print(f"    -> PE Header Offset (e_lfanew): {hex(e_lfanew)}")

            #Parse PE Header (NT Headers)
            #Jump to the location pointed to by e_lfanew
            f.seek(e_lfanew)

            #Read the 4-byte Signature
            pe_signature = f.read(4)
            if pe_signature != b'PE\x00\x00':
                print("[!] Error: Invalid PE Signature (Missing 'PE\\0\0').")
                return
            
            print(f"[+] PE Signature Verified")

            #Parse File Header
            #The File Header starts immediately after 4-byte Signature
            #It is exactly 20 bytes long
            #Structure: Machine(2), Sections(2), Timestamp(4), SymTable(4), 
            #            SymCount(4), OptHeaderSize(2), Characteristics(2)

            file_header_data = f.read(20)

            #Unpack: H (Machine), H (Sections), I (Time), I (Sym), I (SymCnt), H (OptSize), H (Char)
            fields = struct.unpack('<HHIIIHH', file_header_data)

            machine_type = fields[0]
            number_of_sections = fields[1]
            timestamp = fields[2]
            size_of_optional_header = fields[5]
            characteristics = fields[6]

            print(f"[+] File Header Parsed:")
            print(f"    -> Machine Type: {hex(machine_type)} (0x14C=x86, 0x8664=x64)")
            print(f"    -> Number of Sections: {number_of_sections}")
            print(f"    -> Size of Optional Header: {size_of_optional_header} bytes")
            print(f"    -> Characteristics: {hex(characteristics)}")

            #Parse Optional Header (Magic only)
            #We read just enough to see if it's PE32 (32-bit) or PE32+ (64-bit)
            #The first 2 bytes of Optional Header tell us the "Magic" state

            opt_magic_data = f.read(2)
            opt_magic = struct.unpack('<H', opt_magic_data)[0]

            arch = "Unknown"
            if opt_magic == 0x10B:
                arch = "PE32 (32-bit)"
            elif opt_magic == 0x20B:
                arch = "PE32+ (64-bit)"

            print(f"[+] Optional Header Magic: {hex(opt_magic)} ({arch})")

    except FileNotFoundError:
        print("[!] Error: File not found")
    except Exception as e:
        print(f"[!] An error occurred: {e}")

if __name__  == "__main__":
    if len(sys.argv) > 1:
        #Use the file name provided in the terminal
        target_file = sys.argv[1]
        parse_pe_header(target_file)
    else:
        print("[!] Usage: python pe_parser.py <filename>")
    print("[*] Example: python pe_parser.py putty.exe")