import os
import subprocess
import json
import datetime

# Path to Sleuthkit command-line tools
TSK_TOOL_PATH = "E:\\Lab\\Applications\\Sleuthkit\\bin"

# Absolute path to the disk image to be analyzed
p1 = "E:\\Work\\Abdulrhman\\Forensics Platform\\Scripts\\Files\\images\\2020JimmyWilson.E01"
p2 = "E:\\Work\\Abdulrhman\\Forensics Platform\\Scripts\\Files\\mem\\Win10memdump.mem"
IMAGE_PATH = os.path.abspath(p1)

# Create a directory for the output based on the image name
IMAGE_NAME = os.path.basename(IMAGE_PATH).split('.')[0]
OUTPUT_DIR = os.path.join("E:\\Work\\Abdulrhman\\Forensics Platform\\Scripts\\output\\tsk_analysis", IMAGE_NAME)
SCANS_DIR = os.path.join(OUTPUT_DIR, "scans")
os.makedirs(SCANS_DIR, exist_ok=True)

def run_command(command):
    """Run a shell command and return the output."""
    try:
        result = subprocess.run(command, shell=True, capture_output=True, text=True)
        if result.returncode != 0:
            return {"error": result.stderr}
        return {"output": result.stdout}
    except Exception as e:
        return {"error": str(e)}

def save_to_file(filename, content):
    """Save content to a text file."""
    with open(filename, 'w') as file:
        file.write(content)

def save_to_html(filename, content):
    """Save content to an HTML file."""
    with open(filename, 'w') as file:
        file.write(content)

def get_partition_analysis():
    """Run partition analysis."""
    command = f'"{TSK_TOOL_PATH}\\mmls" "{IMAGE_PATH}"'
    result = run_command(command)
    return result

def get_file_system_analysis(partition_offset):
    """Run file system analysis."""
    command = f'"{TSK_TOOL_PATH}\\fsstat" "{IMAGE_PATH}" -o {partition_offset}'
    result = run_command(command)
    return result

def get_file_listing(partition_offset):
    """Run file listing."""
    command = f'"{TSK_TOOL_PATH}\\fls" -r -m "/" "{IMAGE_PATH}" -o {partition_offset}'
    result = run_command(command)
    return result

def get_file_carving():
    """Run file carving."""
    command = f'"{TSK_TOOL_PATH}\\tsk_recover" "{IMAGE_PATH}"'
    result = run_command(command)
    return result

def get_file_hash_calculation():
    """Run file hash calculation."""
    command = f'"{TSK_TOOL_PATH}\\tsk_hash" "{IMAGE_PATH}"'
    result = run_command(command)
    return result

def get_file_metadata_extraction(partition_offset):
    """Run file metadata extraction."""
    command = f'"{TSK_TOOL_PATH}\\fsstat" "{IMAGE_PATH}" -o {partition_offset}'
    result = run_command(command)
    return result

def get_volume_information():
    """Run volume information extraction."""
    command = f'"{TSK_TOOL_PATH}\\blkls" "{IMAGE_PATH}"'
    result = run_command(command)
    return result

def get_file_type_identification():
    """Run file type identification."""
    command = f'"{TSK_TOOL_PATH}\\file" "{IMAGE_PATH}"'
    result = run_command(command)
    return result

def get_disk_image_integrity_check():
    """Run disk image integrity check."""
    command = f'md5sum "{IMAGE_PATH}"'
    result = run_command(command)
    return result

def get_deleted_file_recovery(partition_offset):
    """Run deleted file recovery."""
    command = f'"{TSK_TOOL_PATH}\\tsk_recover" "{IMAGE_PATH}" -o {partition_offset}'
    result = run_command(command)
    return result

def get_filesystem_type_detection():
    """Run filesystem type detection."""
    command = f'"{TSK_TOOL_PATH}\\fsstat" "{IMAGE_PATH}"'
    result = run_command(command)
    return result

def generate_html_report():
    """Generate an HTML report of the analysis."""
    report_content = f"""
    <html>
    <head>
        <title>Disk Image Analysis Report</title>
        <style>
            body {{ font-family: Arial, sans-serif; margin: 20px; }}
            h1 {{ color: #333; }}
            h2 {{ color: #555; }}
            pre {{ background-color: #f9f9f9; padding: 10px; border: 1px solid #ddd; }}
        </style>
    </head>
    <body>
        <h1>Disk Image Analysis Report</h1>
        <h2>Report Generated on {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</h2>
    """
    
    # Add partition analysis
    result = get_partition_analysis()
    report_content += "<h2>Partition Analysis</h2>"
    if "error" in result:
        report_content += f"<pre>Error: {result['error']}</pre>"
    else:
        partition_file = os.path.join(SCANS_DIR, 'partition_analysis.txt')
        save_to_file(partition_file, result['output'])
        report_content += f"<pre>{result['output']}</pre>"

    # Assuming partition number 1 for demonstration
    partition_offset = 0  # Adjust as needed

    # Add file system analysis
    result = get_file_system_analysis(partition_offset)
    report_content += "<h2>File System Analysis</h2>"
    if "error" in result:
        report_content += f"<pre>Error: {result['error']}</pre>"
    else:
        fs_file = os.path.join(SCANS_DIR, 'file_system_analysis.txt')
        save_to_file(fs_file, result['output'])
        report_content += f"<pre>{result['output']}</pre>"

    # Add file listing
    result = get_file_listing(partition_offset)
    report_content += "<h2>File Listing</h2>"
    if "error" in result:
        report_content += f"<pre>Error: {result['error']}</pre>"
    else:
        file_listing_file = os.path.join(SCANS_DIR, 'file_listing.txt')
        save_to_file(file_listing_file, result['output'])
        report_content += f"<pre>{result['output']}</pre>"

    # Add file carving
    result = get_file_carving()
    report_content += "<h2>File Carving</h2>"
    if "error" in result:
        report_content += f"<pre>Error: {result['error']}</pre>"
    else:
        file_carving_file = os.path.join(SCANS_DIR, 'file_carving.txt')
        save_to_file(file_carving_file, result['output'])
        report_content += f"<pre>{result['output']}</pre>"

    # Add file hash calculation
    result = get_file_hash_calculation()
    report_content += "<h2>File Hash Calculation</h2>"
    if "error" in result:
        report_content += f"<pre>Error: {result['error']}</pre>"
    else:
        file_hash_file = os.path.join(SCANS_DIR, 'file_hash_calculation.txt')
        save_to_file(file_hash_file, result['output'])
        report_content += f"<pre>{result['output']}</pre>"

    # Add file metadata extraction
    result = get_file_metadata_extraction(partition_offset)
    report_content += "<h2>File Metadata Extraction</h2>"
    if "error" in result:
        report_content += f"<pre>Error: {result['error']}</pre>"
    else:
        file_metadata_file = os.path.join(SCANS_DIR, 'file_metadata_extraction.txt')
        save_to_file(file_metadata_file, result['output'])
        report_content += f"<pre>{result['output']}</pre>"

    # Add volume information
    result = get_volume_information()
    report_content += "<h2>Volume Information</h2>"
    if "error" in result:
        report_content += f"<pre>Error: {result['error']}</pre>"
    else:
        volume_info_file = os.path.join(SCANS_DIR, 'volume_information.txt')
        save_to_file(volume_info_file, result['output'])
        report_content += f"<pre>{result['output']}</pre>"

    # Add file type identification
    result = get_file_type_identification()
    report_content += "<h2>File Type Identification</h2>"
    if "error" in result:
        report_content += f"<pre>Error: {result['error']}</pre>"
    else:
        file_type_file = os.path.join(SCANS_DIR, 'file_type_identification.txt')
        save_to_file(file_type_file, result['output'])
        report_content += f"<pre>{result['output']}</pre>"

    # Add disk image integrity check
    result = get_disk_image_integrity_check()
    report_content += "<h2>Disk Image Integrity Check</h2>"
    if "error" in result:
        report_content += f"<pre>Error: {result['error']}</pre>"
    else:
        disk_integrity_file = os.path.join(SCANS_DIR, 'disk_image_integrity_check.txt')
        save_to_file(disk_integrity_file, result['output'])
        report_content += f"<pre>{result['output']}</pre>"

    # Add deleted file recovery
    result = get_deleted_file_recovery(partition_offset)
    report_content += "<h2>Deleted File Recovery</h2>"
    if "error" in result:
        report_content += f"<pre>Error: {result['error']}</pre>"
    else:
        deleted_file_recovery_file = os.path.join(SCANS_DIR, 'deleted_file_recovery.txt')
        save_to_file(deleted_file_recovery_file, result['output'])
        report_content += f"<pre>{result['output']}</pre>"

    # Add filesystem type detection
    result = get_filesystem_type_detection()
    report_content += "<h2>Filesystem Type Detection</h2>"
    if "error" in result:
        report_content += f"<pre>Error: {result['error']}</pre>"
    else:
        filesystem_type_file = os.path.join(SCANS_DIR, 'filesystem_type_detection.txt')
        save_to_file(filesystem_type_file, result['output'])
        report_content += f"<pre>{result['output']}</pre>"

    report_content += "</body></html>"

    html_file = os.path.join(OUTPUT_DIR, 'analysis_report.html')
    save_to_html(html_file, report_content)
    print(f"HTML report saved to {html_file}")

# Run the analysis and generate the report
generate_html_report()
