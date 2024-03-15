import idaapi
import idc
import os

# Initialize symbols_dict globally
symbols_dict = {}

def parse_kallsyms(file_path):
    global symbols_dict
    base_address = None  # Initialize base address as None

    with open(file_path, 'r') as file:
        for line in file:
            parts = line.strip().split(' ')
            if len(parts) == 3:
                address, symbol_type, symbol_name = parts
                address = int(address, 16)  # Convert address to integer

                # Look for the _text symbol to determine the base address
                if symbol_name == "_text":
                    base_address = address

                if base_address is not None:
                    # Only populate the dictionary after finding the base address
                    relative_address = address - base_address
                    symbols_dict[hex(relative_address)] = symbol_name  # Store with hex format for consistency

    if base_address is None:
        print("Error: _text symbol not found in kallsyms file.")
        return None

    return base_address  # Return the base address for reference

def rename_symbols_from_kallsyms():
    kallsyms_file_path = idaapi.ask_file(0, "*.*", "Please select the kallsyms file")
    if kallsyms_file_path:
        base_address = parse_kallsyms(kallsyms_file_path)
        
        # Proceed only if the base address was successfully determined
        if base_address is not None:
            print(f"Base address: {hex(base_address)}")
            for address_str, name in symbols_dict.items():
                # Convert relative address from string to integer
                relative_address = int(address_str, 16)
                
                # Rename the symbol in IDA if the relative address maps to a valid segment
                if idc.get_segm_name(relative_address) is not None:
                    idaapi.set_name(relative_address, name, idaapi.SN_NOWARN)
            
            print(f"Processed {len(symbols_dict)} symbols from kallsyms.")
        else:
            print("Failed to determine the base address from kallsyms file.")
    else:
        print("No kallsyms file selected.")

rename_symbols_from_kallsyms()
