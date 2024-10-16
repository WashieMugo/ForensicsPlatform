import os
import hashlib
import subprocess

def create_metadata_folder(output_dir, file_name):
    """Create a metadata folder within the output directory."""
    metadata_dir = os.path.join(output_dir, file_name, 'metadata')
    os.makedirs(metadata_dir, exist_ok=True)
    return metadata_dir

def hash_image(file_path):
    """Generate and return the SHA-256 hash of the image file."""
    hasher = hashlib.sha256()
    with open(file_path, 'rb') as f:
        while chunk := f.read(8192):
            hasher.update(chunk)
    return hasher.hexdigest()

def run_command(command):
    """Run a shell command and return the output."""
    try:
        print(f"Running command: {command}")
        result = subprocess.run(command, shell=True, capture_output=True, text=True)
        if result.returncode != 0:
            print(f"Error running command: {result.stderr}")
            return None  # or return an appropriate error message
        return result.stdout
    except Exception as e:
        print(f"Exception running command: {str(e)}")
        return None

def extract_partitions(file_path, metadata_dir):
    """Extract number of partitions from the disk image."""
    command = [os.path.join(os.getenv('TSK_TOOL_PATH'), 'mmls'), file_path]
    output_file = os.path.join(metadata_dir, 'partitions.txt')
    with open(output_file, 'w') as f:
        output = run_command(command)
        if output:
            f.write(output)

def extract_partition_filetypes(file_path, metadata_dir):
    """Extract file types within each partition."""
    command = [os.path.join(os.getenv('TSK_TOOL_PATH'), 'fls'), file_path]
    output_file = os.path.join(metadata_dir, 'partition_filetypes.txt')
    with open(output_file, 'w') as f:
        output = run_command(command)
        if output:
            f.write(output)

def extract_parent_directory(file_path, metadata_dir):
    """Extract the parent directory information for the files."""
    command = [os.path.join(os.getenv('TSK_TOOL_PATH'), 'fls'), '-r', file_path]
    output_file = os.path.join(metadata_dir, 'parent_directory.txt')
    with open(output_file, 'w') as f:
        output = run_command(command)
        if output:
            f.write(output)

def extract_file_allocation(file_path, metadata_dir):
    """Extract file allocation information."""
    command = [os.path.join(os.getenv('TSK_TOOL_PATH'), 'fsstat'), file_path]
    output_file = os.path.join(metadata_dir, 'file_allocation.txt')
    with open(output_file, 'w') as f:
        output = run_command(command)
        if output:
            f.write(output)

def fetch_image_metadata(file_path, output_dir):
    """Fetch and save image-specific metadata."""
    file_name = os.path.basename(file_path).split('.')[0]
    metadata_dir = create_metadata_folder(output_dir, file_name)

    # Fetching metadata
    image_hash = hash_image(file_path)
    extract_partitions(file_path, metadata_dir)
    extract_partition_filetypes(file_path, metadata_dir)
    extract_parent_directory(file_path, metadata_dir)
    extract_file_allocation(file_path, metadata_dir)

    return {
        'hash': image_hash,
        'metadata_dir': metadata_dir
    }
