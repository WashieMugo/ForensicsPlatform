import os 
import hashlib
import subprocess
import json
from datetime import datetime

def create_metadata_folder(output_dir, file_name):
    """Create a metadata folder within the output directory."""
    metadata_dir = os.path.join(output_dir, file_name, 'metadata')
    os.makedirs(metadata_dir, exist_ok=True)
    return metadata_dir

def hash_memory_dump(file_path):
    """Generate and return the SHA-256 hash of the memory dump."""
    hasher = hashlib.sha256()
    with open(file_path, 'rb') as f:
        while chunk := f.read(8192):
            hasher.update(chunk)
    return hasher.hexdigest()

def extract_user_accounts(file_path, metadata_dir):
    """Extract user accounts from the memory image."""
    command = ['python', os.getenv('VOL_TOOL_PATH'), '-f', file_path, 'windows.hashdump.Hashdump']
    output_file = os.path.join(metadata_dir, 'user_accounts.txt')
    with open(output_file, 'w') as f:
        subprocess.run(command, stdout=f, text=True)
    return output_file

def extract_loaded_modules(file_path, metadata_dir):
    """Extract loaded modules from the memory image."""
    command = ['python', os.getenv('VOL_TOOL_PATH'), '-f', file_path, 'windows.dlllist']
    output_file = os.path.join(metadata_dir, 'loaded_modules.txt')
    with open(output_file, 'w') as f:
        subprocess.run(command, stdout=f, text=True)
    return output_file

def extract_last_processes(file_path, metadata_dir):
    """Extract the last processes from the memory image."""
    command = ['python', os.getenv('VOL_TOOL_PATH'), '-f', file_path, 'windows.pslist']
    output_file = os.path.join(metadata_dir, 'last_processes.txt')
    with open(output_file, 'w') as f:
        subprocess.run(command, stdout=f, text=True)
    return output_file

# Updated function to parse the user accounts file
def parse_user_accounts(file_path):
    """Parse the user accounts file and return a list of accounts."""
    user_accounts = []
    with open(file_path, 'r') as f:
        for line in f:
            # Skip unnecessary lines: Volatility flags, empty lines, and headers
            if "Volatility" in line or "User" in line or not line.strip():
                continue
            fields = line.split()
            if len(fields) >= 4:
                account = {
                    "user": fields[0],
                    "rid": fields[1],
                    "lmhash": fields[2],
                    "nthash": fields[3]
                }
                user_accounts.append(account)
    return user_accounts

# Updated function to parse the last processes file
def parse_last_processes(file_path):
    """Parse the last processes file and return a list of processes."""
    processes = []
    with open(file_path, 'r') as f:
        for line in f:
            # Skip unnecessary lines: Volatility flags, empty lines, and headers
            if "Volatility" in line or "PID" in line or not line.strip():
                continue
            fields = line.split()
            if len(fields) >= 9:
                process = {
                    "pid": fields[0],
                    "ppid": fields[1],
                    "image": fields[2],
                    "createtime": fields[7]
                }
                processes.append(process)
    return processes[:10]  # Return the last 10 processes

# Updated function to parse the loaded modules file
def parse_loaded_modules(file_path):
    """Parse the loaded modules file and return a list of modules."""
    modules = []
    with open(file_path, 'r') as f:
        for line in f:
            # Skip unnecessary lines: Volatility flags, empty lines, and headers
            if "Volatility" in line or "PID" in line or not line.strip():
                continue
            fields = line.split()
            if len(fields) >= 6:
                module = {
                    "pid": fields[0],
                    "name": fields[3],
                    "path": fields[5]
                }
                modules.append(module)
    return modules

def fetch_memory_metadata(file_path, output_dir):
    """Fetch and save memory-specific metadata."""
    file_name = os.path.basename(file_path).split('.')[0]
    metadata_dir = create_metadata_folder(output_dir, file_name)
    # Fetching metadata
    memory_hash = hash_memory_dump(file_path)
        # Extract data and get file paths
    user_accounts_file = extract_user_accounts(file_path, metadata_dir)
    loaded_modules_file = extract_loaded_modules(file_path, metadata_dir)
    last_processes_file = extract_last_processes(file_path, metadata_dir)
    # Parse the files into structured data
    user_accounts = parse_user_accounts(user_accounts_file)
    loaded_modules = parse_loaded_modules(loaded_modules_file)
    last_processes = parse_last_processes(last_processes_file)
    # Return metadata as a JSON object
    metadata = {
        'hash': memory_hash,
        'user_accounts': user_accounts,
        'loaded_modules': loaded_modules,
        'last_processes': last_processes
    }
    return metadata