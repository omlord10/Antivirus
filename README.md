# 🛡️ Simple Antivirus (C Language)

## Overview

This is a basic antivirus implemented in C. It checks executable files for known
malicious byte patterns using a signature-based approach. The antivirus reads a signature
file containing the virus pattern, the offset, and the virus name, and then searches
the target file to detect potential infections.

## 📁 Project Structure

- `antivirus.c` – Main entry point of the application.
- `read_signature()` – Reads the virus signature from a text file.
- `scan_file()` – Checks the specified file for the presence of the signature.
- `calculate_file_size()` – Determines the file size to ensure a valid offset.
- `VirusSignature` – Structure for storing the signature, offset, and name.

## 🧬 Virus Signature Format

Signature file must contain exactly one line with the following format:
<HEX SIGNATURE> <HEX OFFSET> <VIRUS NAME>

### Where:
- `<HEX SIGNATURE>` is a space-separated sequence of bytes in hexadecimal format 
  (e.g., `74 43 6f 6e 74 65 78 74`)
- `<HEX OFFSET>` is an 8-digit hexadecimal number without the `0x` prefix 
  (e.g., `0038d870`)
- `<VIRUS NAME>` is a string describing the virus (e.g., `SUPER-PUPER-VIRUS`)

### Example

    74 43 6f 6e 74 65 78 74 0038d870 SUPER-PUPER-VIRUS

## 🧪 How to Use

To run the antivirus on Windows, follow these steps:

1. **Download the precompiled `antivirus.exe`** from the project repository or provided link.

2. **Run the program** in the command prompt:

    Open Command Prompt and type:

    ```
    antivirus.exe
    ```

3. **Input the file paths when prompted**:

    - First, you will be asked to input the path to the virus signature file (e.g., `signature.txt`).
    - Then, you will be asked to input the path to the file you want to scan (e.g., a `target.exe` file or another file).

### Example Output:
    Welcome to the virus antivirus program!
    Enter path to signature file:
    signature.txt
    Enter path to target file:
    program.exe
    Virus detected: SUPER-PUPER-VIRUS

## ⚠️ Error Handling

The program uses `enum`-based error codes for clear and consistent error reporting. 
If any step fails (e.g., file not found, format invalid), the program will display a corresponding error message 
and exit with an appropriate code.
