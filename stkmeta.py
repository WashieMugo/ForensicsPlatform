import os
import json
import hashlib
import subprocess
from dotenv import load_dotenv

# Load environment variables
load_dotenv('dash.env')
TSK_TOOL_PATH = os.getenv("TSK_TOOL_PATH")

def run_command(command):
    """Run a shell command and return the output."""
    try:
        print(f"Running command: {' '.join(command)}")
        result = subprocess.run(command, capture_output=True, text=True)
        if result.returncode != 0:
            print(f"Error running command: {result.stderr}")
            return None
        return result.stdout
    except Exception as e:
        print(f"Exception running command: {str(e)}")
        return None

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

def extract_partitions(file_path, metadata_dir):
    """Extract number of partitions from the disk image."""
    command = [os.path.join(TSK_TOOL_PATH, 'mmls'), file_path]
    output_file = os.path.join(metadata_dir, 'partitions.txt')
    output = run_command(command)
    if output:
        with open(output_file, 'w') as f:
            f.write(output)

def run_partition_analysis(start, file_path, metadata_dir):
    """Run partition analysis using fsstat and save output to a text file."""
    clean_start = start.lstrip('0')  # Strip leading zeros from the offset
    command = [os.path.join(TSK_TOOL_PATH, 'fsstat'), '-o', clean_start, file_path]
    output_file = os.path.join(metadata_dir, f'partition_analysis_{clean_start}.txt')
    output = run_command(command)
    if output:
        with open(output_file, 'w') as f:
            f.write(output)
    return output_file

def list_top_directories(start, file_path, metadata_dir):
    """List top directories using fls and save output to a text file."""
    clean_start = start.lstrip('0')  # Strip leading zeros from the offset
    command = [os.path.join(TSK_TOOL_PATH, 'fls'), '-o', clean_start, file_path]
    output_file = os.path.join(metadata_dir, f'top_directories_{clean_start}.txt')
    output = run_command(command)
    if output:
        with open(output_file, 'w') as f:
            f.write(output)
    return output_file

def extract_valid_partitions(metadata_dir, file_path):
    """Extract valid partitions from partitions.txt and return a dictionary."""
    partitions_file = os.path.join(metadata_dir, 'partitions.txt')
    valid_partitions = {}
    
    try:
        with open(partitions_file, 'r') as f:
            lines = f.readlines()
            for line in lines:
                # Skip invalid partitions
                if any(keyword in line for keyword in ['unallocated', 'Table', 'Meta', '-------']):
                    continue
                
                # Extract fields from the valid partition line
                fields = line.split()
                if len(fields) >= 6:
                    index = fields[0]
                    slot = fields[1]
                    start = fields[2]
                    end = fields[3]
                    length = fields[4]
                    description = ' '.join(fields[5:])
                    
                    valid_partitions[f'partition_{index}'] = {
                        'index': index,
                        'slot': slot,
                        'start': start,
                        'end': end,
                        'length': length,
                        'description': description
                    }
                    
    except Exception as e:
        print(f"Error reading partitions file: {str(e)}")
        return None
    
    return valid_partitions

def analyze_partitions(valid_partitions, file_path, metadata_dir):
    """Perform operations on each valid partition and store results separately."""
    partition_analysis_results = {}
    
    for partition_id, partition_data in valid_partitions.items():
        start = partition_data['start']
        
        # Run partition analysis and save output
        partition_analysis_file = run_partition_analysis(start, file_path, metadata_dir)
        
        # List top directories and save output
        top_directories_file = list_top_directories(start, file_path, metadata_dir)
        
        # Store results for each partition
        partition_analysis_results[partition_id] = {
            'partition_analysis_file': partition_analysis_file,
            'top_directories_file': top_directories_file
        }
    
    return partition_analysis_results

def parse_partition_analysis(file_path):
    """Parse the partition analysis text file and return metadata as a dictionary."""
    metadata = {}
    current_section = None
    
    try:
        with open(file_path, 'r') as f:
            content = f.read()
            sections = content.split("\n\n")  # Split by double new lines
            
            for section in sections:
                lines = section.splitlines()
                if lines:
                    # The first line is the header
                    header = lines[0].strip()
                    if header not in metadata:  # Create a new section if not already present
                        metadata[header] = {}
                        current_section = header
                    
                    # Skip dashed lines
                    for line in lines[1:]:
                        line = line.strip()
                        if line and not line.startswith('-'):
                            if ':' in line:  # Check if line contains a key-value pair
                                key, value = line.split(':', 1)
                                metadata[current_section][key.strip()] = value.strip()
                            else:
                                # If there is no ':' assume it is part of the previous section or a standalone value
                                metadata[current_section][line] = None

    except Exception as e:
        print(f"Error parsing partition analysis file: {str(e)}")
    
    return metadata

def parse_top_directories(file_path):
    """Parse the top directories text file and return a list of directory entries."""
    entries = []
    
    try:
        with open(file_path, 'r') as f:
            lines = f.readlines()
            for line in lines:
                line = line.strip()
                if line:
                    parts = line.split(":")
                    if len(parts) == 2:
                        entry_type, file_name = parts
                        entries.append({
                            'type': entry_type.strip(),
                            'file_name': file_name.strip()
                        })
    except Exception as e:
        print(f"Error parsing top directories file: {str(e)}")
    
    return entries

def fetch_image_metadata(file_path, output_dir):
    """Fetch and save image-specific metadata."""
    file_name = os.path.basename(file_path).split('.')[0]
    metadata_dir = create_metadata_folder(output_dir, file_name)

    # Fetching metadata
    image_hash = hash_image(file_path)
    extract_partitions(file_path, metadata_dir)
    
    # Extract valid partitions
    valid_partitions = extract_valid_partitions(metadata_dir, file_path)

    # Convert valid_partitions from dictionary to list for easier handling in the template
    valid_partitions_list = [{'index': v['index'], 'slot': v['slot'], 'start': v['start'], 'end': v['end'], 'length': v['length'], 'description': v['description']} for v in valid_partitions.values()]

    # Perform additional operations on partitions
    partition_operations = analyze_partitions(valid_partitions, file_path, metadata_dir)

    # Parse the metadata from each partition analysis file
    parsed_partition_metadata = {}
    for partition_id, results in partition_operations.items():
        parsed_metadata = parse_partition_analysis(results['partition_analysis_file'])
        parsed_partition_metadata[partition_id] = parsed_metadata

    # Parse the top directories
    parsed_top_directories = {}
    for partition_id, results in partition_operations.items():
        parsed_directories = parse_top_directories(results['top_directories_file'])
        parsed_top_directories[partition_id] = parsed_directories

    # Construct metadata
    metadata = {
        'hash': image_hash,
        'metadata_dir': metadata_dir,
        'valid_partitions': valid_partitions_list,  # Change to list
        'partition_metadata': parsed_partition_metadata,  # Add parsed metadata
        'top_directories': parsed_top_directories  # Add parsed top directories
    }

    return metadata
