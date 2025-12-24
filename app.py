from flask import Flask, render_template, request
import struct
import os

app = Flask(__name__)

def get_pe_info(file_stream):
    info = {'warnings': [], 'status': 'Clean'}
    try:
        # --- 0. Get Actual File Size ---
        file_stream.seek(0, os.SEEK_END)
        actual_file_size = file_stream.tell()
        file_stream.seek(0) # Reset to start

        # --- 1. MS-DOS Header ---
        e_magic = file_stream.read(2).decode('utf-8', errors='ignore')
        if e_magic != 'MZ': return {"error": "Invalid PE (No MZ)"}
        
        file_stream.seek(0x3C)
        e_lfanew = struct.unpack('<I', file_stream.read(4))[0]
        info['e_lfanew'] = hex(e_lfanew)

        # --- 2. PE Signature ---
        file_stream.seek(e_lfanew)
        if file_stream.read(4) != b'PE\x00\x00': return {"error": "Invalid PE Signature"}

        # --- 3. COFF File Header ---
        file_header_data = file_stream.read(20)
        fields = struct.unpack('<HHIIIHH', file_header_data)
        
        info['machine'] = hex(fields[0])
        num_sections = fields[1]
        info['num_sections'] = num_sections
        info['timestamp'] = fields[2]
        size_of_optional_header = fields[5]

        # --- 4. Optional Header ---
        opt_header_data = file_stream.read(size_of_optional_header)
        opt_magic = struct.unpack('<H', opt_header_data[:2])[0]
        
        entry_point_rva = 0
        if opt_magic == 0x20B: 
            info['arch'] = "PE32+ (64-bit)"
            entry_point_rva = struct.unpack('<I', opt_header_data[16:20])[0]
            image_base = struct.unpack('<Q', opt_header_data[24:32])[0]
        elif opt_magic == 0x10B:
            info['arch'] = "PE32 (32-bit)"
            entry_point_rva = struct.unpack('<I', opt_header_data[16:20])[0]
            image_base = struct.unpack('<I', opt_header_data[28:32])[0]
        else:
            info['arch'] = "Unknown"
            image_base = 0

        info['entry_point'] = hex(entry_point_rva)
        info['image_base'] = hex(image_base)

        # --- 5. Section Headers & Safety Checks ---
        section_table_start = e_lfanew + 4 + 20 + size_of_optional_header
        file_stream.seek(section_table_start)

        sections = []
        entry_point_in_section = False

        for _ in range(num_sections):
            section_data = file_stream.read(40)
            sec_fields = struct.unpack('<8sIIII3II', section_data)
            
            name = sec_fields[0].decode('utf-8', errors='ignore').strip('\x00')
            v_addr = sec_fields[2]  # Virtual Address (RVA)
            v_size = sec_fields[1]  # Virtual Size
            raw_size = sec_fields[3]
            raw_ptr = sec_fields[4]
            characteristics = sec_fields[8]

            # SECURITY CHECK 1: File Corruption
            # If the section claims to be at an offset larger than the file size
            if raw_ptr + raw_size > actual_file_size:
                info['warnings'].append(f"Corruption: Section '{name}' is truncated (goes past end of file).")
                info['status'] = 'Corrupted'

            # SECURITY CHECK 2: Writable & Executable (RWX)
            # 0x20000000 = Executable, 0x80000000 = Writable
            is_exec = characteristics & 0x20000000
            is_write = characteristics & 0x80000000
            
            if is_exec and is_write:
                info['warnings'].append(f"Suspicious: Section '{name}' is both WRITABLE and EXECUTABLE (often used by malware/packers).")
                if info['status'] != 'Corrupted':
                    info['status'] = 'Suspicious'

            # SECURITY CHECK 3: Check if Entry Point lands in this section
            if v_addr <= entry_point_rva < (v_addr + v_size):
                entry_point_in_section = True

            sections.append({
                'name': name,
                'virtual_address': hex(v_addr),
                'raw_size': raw_size,
                'raw_pointer': hex(raw_ptr),
                'characteristics': hex(characteristics)
            })
            
        if not entry_point_in_section and entry_point_rva != 0:
             info['warnings'].append("Suspicious: Entry Point does not point to any known section.")
             if info['status'] != 'Corrupted':
                    info['status'] = 'Suspicious'

        info['sections'] = sections
        return info

    except Exception as e:
        return {"error": f"Error parsing file: {str(e)}"}

@app.route('/', methods=['GET', 'POST'])
def index():
    data = None
    if request.method == 'POST':
        # Check if file is part of the request
        if 'file' not in request.files:
            return render_template('index.html', error="No file uploaded")
        
        file = request.files['file']
        
        if file.filename == '':
            return render_template('index.html', error="No file selected")

        if file:
            # Process the file directly from memory (no need to save to disk first)
            data = get_pe_info(file)
            data['filename'] = file.filename

    return render_template('index.html', data=data)

if __name__ == '__main__':
    app.run(debug=True)