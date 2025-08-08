# Raw Disk Parser

A proof-of-concept Python script to dump sensitive/restricted files (`SAM`, `SYSTEM`, `NTDS.dit`) without triggering alerts. It works by reading directly from the physical disk, then parsing out NTFS filesystem structures to locate and read files. This method doesn't call standard Windows file APIs, so it effectively evades file access controls, exclusive file locks, and certain EDR/AV monitoring capabilities that rely on hooking high-level file I/O operations.

For a detailed technical breakdown of the technique, see the accompanying blog post: [Leveraging Raw Disk Reads to Bypass EDR](TODO: BLOG LINK HERE).

**DISCLAIMER:** This tool is for educational and research purposes only. I am not responsible for how you use it. Only use this in a test environment. This has not been tested against all systems and in all conditions, and there may be unknown side effects/cause issues with the test machine.



https://github.com/user-attachments/assets/a1555d4c-7e59-4a83-b1db-b2ac24e137d1

---

## Requirements

-   Python 3.x
-   Admin privileges
-   Bitlocker disabled


## Usage

1.  Open a Command Prompt or PowerShell terminal **as an Administrator**.
2.  **Execute the Script:**
    ```shell
    python raw_disk_parser.py
    ```
3.  **Retrieve Output:** If successful, the script will create a file named `hives_dump.zip` in the current directory. This archive will contain the XOR-encrypted hive files, such as `sam.xored` and `system.xored`.

## Decrypting the Output Files

The dumped files are XOR-encrypted with the key `bobbert` to avoid alerts that trigger when SAM/SYSTEM/etc. is written to disk. If you're feeling lazy and the credentials you dumped are not sensitive, [cyber chef](https://gchq.github.io/CyberChef/#recipe=XOR(%7B'option':'UTF8','string':'bobbert'%7D,'Standard',false)) can decrypt the files for verification. If not, you can transfer the files off the victim, and use the accompanying (or similar) XOR decryption script.

**Example:**
```shell
python simple_xor.py sam.xored SAM.hive
```

## How It Works

1.  **Gain Handle:** The script first acquires a read handle to the primary physical disk (`\\.\PhysicalDrive0`)
2.  **Find Partition:** It reads Sector 0 to parse the MBR or GPT, identifying the starting location (LBA) of the main Windows NTFS partition
3.  **Parse VBR:** It reads the Volume Boot Record from the start of the partition to get critical parameters, most importantly the starting cluster number of the `$MFT`
4.  **Locate `$MFT` Data:** It reads the first record of the `$MFT` (which is the record for the `$MFT` file itself) to find its `$DATA` attribute. This attribute contains "data runs" that point to all the locations on disk where the `$MFT` is stored
5.  **Scan `$MFT`:** The script iterates through all the `$MFT` data runs, looking for `$FILE_NAME` attributes that match its targets (`SAM`, `SYSTEM`, or `ntds.dit`)
6.  **Extract File Content:** Once a target file record is found, the script finds its `$DATA` attribute.
    * If the data is **resident**, it's read directly from the MFT record.
    * If the data is **non-resident**, the script follows the data runs to piece together the full file content from various locations on the disk.
7.  **Package and Obfuscate:** The raw file contents are read into memory, XORed with a hardcoded key, and written to a ZIP archive (`hives_dump.zip`). This is done because a lot of EDRs will alert if they see a sensitive hive written to disk (even if they don't necessarily know where it came from)

## Reporting issues
This code is released as a proof-of-concept tool, and it may not be actively maintained; however, the best way to report an issue is still to create an issue in the project, and I will try to resolve it as soon as possible.
