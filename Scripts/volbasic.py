import subprocess
import os

# Set the path to the Volatility executable
VOLATILITY_PATH = "C:\\dev\\volatility3\\vol.py"
# Predefined output directory for memory dumps
OUTPUT_DIR = "output\\vol"

def execute_volatility_command(command):
    """Execute a Volatility command and print the result."""
    try:
        print(f"Executing command: {command}")  # Print command for debugging
        output = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT).decode('utf-8')
        print(output)
    except subprocess.CalledProcessError as e:
        print(f"Error executing command '{command}': {e.output.decode('utf-8')}")

def display_system_info(memory_dump_path):
    """Display system information from the memory dump."""
    command = f"python {VOLATILITY_PATH} -f \"{memory_dump_path}\" windows.info.Info"
    execute_volatility_command(command)

def display_process_list(memory_dump_path):
    """Display the list of processes from the memory dump."""
    command = f"python {VOLATILITY_PATH} -f \"{memory_dump_path}\" windows.pslist.PsList"
    execute_volatility_command(command)

def scan_for_files(memory_dump_path):
    """Scan for files in the memory dump."""
    command = f"python {VOLATILITY_PATH} -f \"{memory_dump_path}\" windows.filescan.FileScan"
    execute_volatility_command(command)

def list_registry_hives(memory_dump_path):
    """List the registry hives in the memory dump."""
    command = f"python {VOLATILITY_PATH} -f \"{memory_dump_path}\" windows.registry.hivelist.HiveList"
    execute_volatility_command(command)

def dump_process_memory(memory_dump_path, pid):
    """Dump the memory of a specific process."""
    # Ensure the output directory exists
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    command = f"python {VOLATILITY_PATH} -f \"{memory_dump_path}\" --pid {pid} windows.memmap.Memmap --dump-dir \"{OUTPUT_DIR}\""
    execute_volatility_command(command)

def extract_loaded_dlls(memory_dump_path):
    """List the DLLs loaded by each process."""
    command = f"python {VOLATILITY_PATH} -f \"{memory_dump_path}\" windows.dlllist.DllList"
    execute_volatility_command(command)

def scan_network_connections(memory_dump_path):
    """Scan the memory dump for network connections."""
    command = f"python {VOLATILITY_PATH} -f \"{memory_dump_path}\" windows.netscan.NetScan"
    execute_volatility_command(command)

def main():
    print("Volatility Basic Functions")
    print("1. Display System Information")
    print("2. Display Process List")
    print("3. Scan for Files")
    print("4. List Registry Hives")
    print("5. Dump Process Memory")
    print("6. Extract Loaded DLLs")
    print("7. Scan for Network Connections")
    print("8. Exit")
    
    # Define the relative path to the memory dump
    relative_path = "Files\\mem\\Win10memdump.mem"
    memory_dump_path = os.path.abspath(relative_path)

    while True:
        choice = input("Enter your choice: ")
        if choice == '1':
            display_system_info(memory_dump_path)
        elif choice == '2':
            display_process_list(memory_dump_path)
        elif choice == '3':
            scan_for_files(memory_dump_path)
        elif choice == '4':
            list_registry_hives(memory_dump_path)
        elif choice == '5':
            pid = input("Enter the PID of the process to dump memory: ")
            dump_process_memory(memory_dump_path, pid)
        elif choice == '6':
            extract_loaded_dlls(memory_dump_path)
        elif choice == '7':
            scan_network_connections(memory_dump_path)
        elif choice == '8':
            print("Exiting the application.")
            break
        else:
            print("Invalid choice. Please try again.")

if __name__ == "__main__":
    main()