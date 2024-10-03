import os
import subprocess
import json
import datetime
import re
from dotenv import load_dotenv
import sys

# Load environment variables from dash.env
load_dotenv('dash.env')

# Path to Sleuthkit command-line tools and output directory from .env
TSK_TOOL_PATH = os.getenv("TSK_TOOL_PATH")
TSK_OUTPUT_DIR = os.getenv("TSK_OUTPUT_DIR")

# Absolute path to the disk image to be analyzed (to be provided as a command-line argument)
IMAGE_PATH = os.path.abspath(sys.argv[1])  # Assuming the file path is passed as the first argument

# Create a directory for the output based on the image name
IMAGE_NAME = os.path.basename(IMAGE_PATH).split('.')[0]
OUTPUT_DIR = os.path.join(TSK_OUTPUT_DIR, IMAGE_NAME)
SCANS_DIR = os.path.join(OUTPUT_DIR, "scans")
os.makedirs(SCANS_DIR, exist_ok=True)

def run_command(command):
    """Run a shell command and return the output."""
    try:
        print(f"Running command: {command}")
        result = subprocess.run(command, shell=True, capture_output=True, text=True)
        if result.returncode != 0:
            return {"error": result.stderr}
        return {"output": result.stdout}
    except Exception as e:
        return {"error": str(e)}

def save_to_file(filename, content):
    """Save content to a text file."""
    try:
        with open(filename, 'w') as file:
            file.write(content)
        print(f"Saved to {filename}")
    except Exception as e:
        print(f"Error saving file {filename}: {str(e)}")

def log_message(message):
    """Log messages to a file."""
    log_file = os.path.join(OUTPUT_DIR, "analysis_log.txt")
    with open(log_file, 'a') as log:
        log.write(f"{datetime.datetime.now()} - {message}\n")
    print(message)

def get_partition_analysis():
    """Run partition analysis."""
    command = f'"{TSK_TOOL_PATH}\\mmls" "{IMAGE_PATH}"'
    result = run_command(command)
    if "error" in result:
        log_message(f"Partition analysis failed: {result['error']}")
    return result

def get_disk_image_integrity_check():
    """Run disk image integrity check."""
    command = f'md5sum "{IMAGE_PATH}"'
    result = run_command(command)
    if "error" in result:
        log_message(f"Disk integrity check failed: {result['error']}")
    return result

def fetch_partitions():
    """Read and extract partition details from partition_analysis.txt."""
    partition_file = os.path.join(SCANS_DIR, 'partition_analysis.txt')
    
    if not os.path.exists(partition_file):
        print(f"Partition analysis file {partition_file} not found!")
        return None

    partitions = []
    
    with open(partition_file, 'r') as file:
        lines = file.readlines()

    # Regex pattern to match partition lines (starts with slot number, followed by partition details)
    partition_pattern = r'^(\d{3}:\s*\S+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(.+)'

    # Parsing the file content to extract partition information
    for line in lines:
        match = re.match(partition_pattern, line)
        if match:
            # Extract slot, start, end, length, and description from the matched line
            partition_data = {
                "Slot": match.group(1),
                "Start": match.group(2),
                "End": match.group(3),
                "Length": match.group(4),
                "Description": match.group(5)
            }
            partitions.append(partition_data)

    if partitions:
        # Log the partition data
        print("Extracted Partition Information:")
        for partition in partitions:
            print(partition)
    else:
        print("No partitions found in the analysis file.")

    return partitions

def run_command_and_write(command, file):
    """Run a shell command and write its output to a file."""
    try:
        # Run command
        result = subprocess.run(command, shell=True, capture_output=True, text=True)
        # Check if command was successful
        if result.returncode == 0:
            file.write(result.stdout)
        else:
            file.write(f"Error executing command: {result.stderr}\n")
    except Exception as e:
        file.write(f"Exception occurred: {str(e)}\n")

def fetch_partitions_with_filter():
    """Fetch partition details and run analysis while skipping invalid partitions."""
    partitions = fetch_partitions()
    
    if partitions is None:
        return
    
    for partition in partitions:
        slot = partition['Slot']
        start = partition['Start']
        description = partition['Description']
        
        # Skip partitions based on improved conditions
        if 'meta' in slot.lower() or 'reserved' in description.lower() or 'table' in description.lower() or 'unallocated' in description.lower():
            continue
        
        # Extract numeric part of slot (before ':')
        slot_num = slot.split(':')[0].strip()
        
        # Create a file for each valid partition
        output_file = os.path.join(SCANS_DIR, f"partition_{slot_num}.txt")
        
        with open(output_file, 'w') as file:
            # Write header with partition info
            file.write(f"<h1>Analysis for Partition {slot}</h1>\n")
            file.write(f"<h2>Description: {description}</h2>\n\n")
            
            # File System Statistics
            file.write("<h2>File System Statistics</h2>\n")
            run_command_and_write(f'"{TSK_TOOL_PATH}\\fsstat" -o {start} "{IMAGE_PATH}"', file)
            
            # Top file directory listing
            file.write("<h2>Top File Directory Listing</h2>\n")
            run_command_and_write(f'"{TSK_TOOL_PATH}\\fls" -o {start} "{IMAGE_PATH}"', file)
            
            # Directories
            file.write("<h2>Directories</h2>\n")
            run_command_and_write(f'"{TSK_TOOL_PATH}\\fls" -r -o {start} "{IMAGE_PATH}" | findstr /R "^d"', file)
            
            # Executables & Compressed Files
            file.write("<h2>Executables </h2>\n")
            run_command_and_write(f'"{TSK_TOOL_PATH}\\fls" -r -o {start} "{IMAGE_PATH}" | findstr /I "\.exe \.bat \.vbs"', file)
   
            # Documents
            file.write("<h2>Documents</h2>\n")
            run_command_and_write(f'"{TSK_TOOL_PATH}\\fls" -r -o {start} "{IMAGE_PATH}" | findstr /I "\.xlsx \.pptx \.docx \.pdf"', file)
            
            # Compressed Files
            file.write("<h2>Compressed Files</h2>\n")
            run_command_and_write(f'"{TSK_TOOL_PATH}\\fls" -r -o {start} "{IMAGE_PATH}" | findstr /I "\.tar \.7z \.rar \.zip"', file)
            
            # Databases
            file.write("<h2>Databases</h2>\n")
            run_command_and_write(f'"{TSK_TOOL_PATH}\\fls" -r -o {start} "{IMAGE_PATH}" | findstr /I "\.db \.sqlite"', file)
            
            # Mail & Communications
            file.write("<h2>Mail & Communications</h2>\n")
            run_command_and_write(f'"{TSK_TOOL_PATH}\\fls" -r -o {start} "{IMAGE_PATH}" | findstr /I "\.pst \.ost \.eml \.msg" ', file)

            # Last 20 linked, allocated, and used inodes
            file.write("<h2>Last 20 Inodes</h2>\n")
            run_command_and_write(f'"{TSK_TOOL_PATH}\\ils" -o {start} -l -a -Z -m "{IMAGE_PATH}" | tail -n 20', file)

def run_command_and_write(command, file):
    """Run command and write output to a file."""
    result = run_command(command)
    if "error" in result:
        file.write(f"Error executing {command}: {result['error']}\n")
    else:
        file.write(result['output'])

def generate_html_report():
    """Generate an HTML report of the analysis."""
    report_content = f"""
    <html>
    <head>
        <title>TSK (Autopsy) Disk Image Analysis Report for {IMAGE_NAME}</title>
        <style>
            body {{ font-family: Arial, sans-serif; margin: 20px; }}
            h1 {{ color: #333; }}
            h2 {{ color: #555; }}
            pre {{ background-color: #f9f9f9; padding: 10px; border: 1px solid #ddd; }}
            table {{ border-collapse: collapse; width: 100%; }}
            table, th, td {{ border: 1px solid black; padding: 8px; }}
        </style>
    </head>
    <body>
        <h1>Disk Image Analysis Report</h1>
        <h2>Report Generated on {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</h2>
    """

    # Add partition analysis
    report_content += "<h2>Partition Analysis</h2>"
    partition_file = os.path.join(SCANS_DIR, 'partition_analysis.txt')
    if os.path.exists(partition_file):
        with open(partition_file, 'r') as file:
            report_content += f"<pre>{file.read()}</pre>"
    else:
        report_content += "<pre>Partition analysis file not found.</pre>"

    # Add disk image integrity check
    report_content += "<h2>Disk Image Integrity Check</h2>"
    integrity_file = os.path.join(SCANS_DIR, 'disk_integrity.txt')
    if os.path.exists(integrity_file):
        with open(integrity_file, 'r') as file:
            report_content += f"<pre>{file.read()}</pre>"
    else:
        report_content += "<pre>Disk integrity file not found.</pre>"

    # Add additional files
    report_content += "<h2>Additional Partition Analysis Files</h2>"
    for filename in os.listdir(SCANS_DIR):
        if filename.startswith("partition_") and filename.endswith(".txt"):
            with open(os.path.join(SCANS_DIR, filename), 'r') as file:
                report_content += f"<h3>{filename}</h3><pre>{file.read()}</pre>"

    report_content += "</body></html>"

    report_file = os.path.join(OUTPUT_DIR, 'analysis_report.html')
    try:
        with open(report_file, 'w') as file:
            file.write(report_content)
        print(f"HTML report generated: {report_file}")
    except Exception as e:
        print(f"Error generating HTML report: {str(e)}")

def main():
    log_message("Starting analysis...")

    # Run partition analysis and disk image integrity check
    partition_result = get_partition_analysis()
    if "error" in partition_result:
        log_message(f"Partition analysis failed: {partition_result['error']}")
    else:
        save_to_file(os.path.join(SCANS_DIR, 'partition_analysis.txt'), partition_result['output'])
    
    integrity_result = get_disk_image_integrity_check()
    if "error" in integrity_result:
        log_message(f"Disk integrity check failed: {integrity_result['error']}")
    else:
        save_to_file(os.path.join(SCANS_DIR, 'disk_integrity.txt'), integrity_result['output'])

    # Fetch and process partitions
    fetch_partitions_with_filter()

    # Generate the HTML report
    generate_html_report()

    log_message("Analysis completed and report generated.")

if __name__ == "__main__":
    main()