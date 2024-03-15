# IDA-KallsymsSymbolRenamer

IDA-KallsymsSymbolRenamer is a Python script for the IDA Pro disassembler that automates the process of renaming symbols based on Android kernel `kallsyms` files. This script enhances the analysis of kernel binaries by aligning symbols in IDA with those found in the `kallsyms` symbol table, making reverse engineering tasks more intuitive and efficient.

## Features

- **Automatic Symbol Renaming**: Parses `kallsyms` files to rename symbols within IDA Pro, improving the readability and navigability of disassembled code.
- **Base Address Calculation**: Determines the base address using the `_text` symbol from the `kallsyms` file, ensuring that symbol addresses are correctly offset in the IDA database.
- **User-friendly File Selection**: Provides a file selection dialog to easily choose the `kallsyms` file without worrying about file extensions.

## Prerequisites

- IDA Pro with IDAPython plugin installed.

## Usage

1. Ensure your IDA Pro environment is set up and the target kernel binary is loaded.
2. Run `IDA-KallsymsSymbolRenamer.py` within IDA's Python console or through the File -> Script file menu.
3. When prompted, select your `kallsyms` file. The script will then process the file and rename symbols accordingly.


