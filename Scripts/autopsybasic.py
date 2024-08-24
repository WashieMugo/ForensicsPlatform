import os
import subprocess
import re

# Path to Sleuthkit command-line tools
TSK_TOOL_PATH = "E:\\Lab\\Applications\\Sleuthkit\\bin"

# Absolute path to the disk image to be analyzed
IMAGE_PATH = os.path.abspath("E:\\Work\\Abdulrhman\\Forensics Platform\\Scripts\\Files\\images\\2020JimmyWilson.E01")

# Absolute path for the analysis output
OUTPUT_PATH = os.path.abspath("E:\\Work\\Abdulrhman\\Forensics Platform\\Scripts\\output\\tsk_analysis")

# Ensure output directory exists
os.makedirs(OUTPUT_PATH, exist_ok=True)

# Define commands
list_partitions_command = f'"{TSK_TOOL_PATH}\\mmls" "{IMAGE_PATH}"'
fsstat_command_template = f'"{TSK_TOOL_PATH}\\fsstat" "{IMAGE_PATH}" -o {{offset}}'
files_command_template = f'"{TSK_TOOL_PATH}\\fls" -r -m "/" "{IMAGE_PATH}" -o {{offset}}'

# Function to execute command and return output
def execute_command(command):
    try:
        result = subprocess.run(command, shell=True, text=True, capture_output=True)
        if result.returncode != 0:
            print(f"Error executing command: {command}")
            print(f"Return Code: {result.returncode}")
            print(f"Stderr: {result.stderr}")
        return result.stdout
    except Exception as e:
        print(f"Exception occurred while executing command: {command}")
        print(f"Exception: {e}")
        return ""

# Verify if the image file exists
if not os.path.isfile(IMAGE_PATH):
    print(f"Error: The image file does not exist at the path: {IMAGE_PATH}")
else:
    # Get partition details
    partitions_output = execute_command(list_partitions_command)
    print("Partitions Output:")
    print(partitions_output)  # Print raw output for debugging

    # Extract partition offset from the output
    partition_offset_match = re.search(r'(\d+):\s+(\d+)', partitions_output)
    if partition_offset_match:
        partition_number = partition_offset_match.group(1)
        partition_offset = partition_offset_match.group(2)

        print(f"Partition Number: {partition_number}")
        print(f"Partition Offset (Decimal): {partition_offset}")

        # Correct offset for fsstat and fls commands
        fsstat_command = fsstat_command_template.format(offset=partition_offset)
        print(f"Executing: {fsstat_command}")  # Debugging command
        fsstat_output = execute_command(fsstat_command)
        print("File System Type Check:")
        print(fsstat_output)  # Print raw output for debugging

        # Example regex to extract file system type (adjust based on actual output)
        fs_type_match = re.search(r'File System Type:\s+(\S+)', fsstat_output)
        file_system_type = fs_type_match.group(1) if fs_type_match else "unknown"

        # Get file list and inode numbers
        files_command = files_command_template.format(offset=partition_offset)
        print(f"Executing: {files_command}")  # Debugging command
        files_output = execute_command(files_command)
        print("Files Output:")
        print(files_output)  # Print raw output for debugging

        # Example regex to extract inode numbers (adjust based on actual output)
        inode_matches = re.findall(r'(\d+)\s+(\S+)', files_output)
        inodes = [match[0] for match in inode_matches]

        # Output file system type and inodes for debugging
        print(f"File System Type: {file_system_type}")
        print(f"Inodes: {inodes}")

        # Example command definitions using the extracted information
        if inodes:
            example_inode = inodes[0]  # Take the first inode for demonstration purposes

            # Commands to fetch metadata and file content
            file_metadata_command = f'"{TSK_TOOL_PATH}\\istat" -f {file_system_type} {partition_image_path} {example_inode} > "{OUTPUT_PATH}\\metadata.txt"'
            extract_file_command = f'"{TSK_TOOL_PATH}\\icat" -f {file_system_type} {partition_image_path} {example_inode} > "{OUTPUT_PATH}\\file_content.txt"'

            # Execute commands
            commands = [
                file_metadata_command,
                extract_file_command
            ]

            for command in commands:
                print(f"Executing: {command}")
                execute_command(command)
        else:
            print("No inodes found. Check the file listing output.")
    else:
        print("Could not determine partition offset from `mmls` output.")