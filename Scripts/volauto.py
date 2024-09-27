import os
import subprocess
import json
import datetime


# Path to Volatility command-line tool
VOL_TOOL_PATH = "C:\\dev\\volatility3\\vol.py"

# Absolute path to the memory image to be analyzed
p1 = "D:\\Work\\Abdulrhman\\Forensics Platform\\Scripts\\Files\\mem\\Win10memdump.mem"
IMAGE_PATH = os.path.abspath(p1)

# Create a directory for the output based on the image name
IMAGE_NAME = os.path.basename(IMAGE_PATH).split('.')[0]
OUTPUT_DIR = os.path.join("D:\\Work\\Abdulrhman\\Forensics Platform\\Scripts\\output\\vol", IMAGE_NAME)
SCANS_DIR = os.path.join(OUTPUT_DIR, "scans")
os.makedirs(SCANS_DIR, exist_ok=True)

def run_command(command):
    """Run a shell command and return the output."""
    print(f"Running command: {command}")
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

def get_profile_detection():
    """Detect the profile of the memory image."""
    command = f'python "{VOL_TOOL_PATH}" -f "{IMAGE_PATH}" windows.info'
    result = run_command(command)
    return result

def get_process_list():
    """List running processes."""
    command = f'python "{VOL_TOOL_PATH}" -f "{IMAGE_PATH}" windows.pslist'
    result = run_command(command)
    return result

def get_network_connections():
    """List network connections."""
    command = f'python "{VOL_TOOL_PATH}" -f "{IMAGE_PATH}" windows.netscan'
    result = run_command(command)
    return result

def get_registry_hives():
    """Dump registry hives."""
    command = f'python "{VOL_TOOL_PATH}" -f "{IMAGE_PATH}" windows.registry.hivelist.HiveList'
    result = run_command(command)
    return result

def get_user_accounts():
    """List user accounts."""
    command = f'python "{VOL_TOOL_PATH}" -f "{IMAGE_PATH}" windows.hashdump.Hashdump'
    result = run_command(command)
    return result

def get_kernel_modules():
    """List kernel modules."""
    command = f'python "{VOL_TOOL_PATH}" -f "{IMAGE_PATH}" windows.modules'
    result = run_command(command)
    return result

def generate_html_report():
    """Generate an HTML report of the analysis."""
    print("Starting report generation...")
    
    report_content = f"""
    <html>
    <head>
        <title>Volatility Analysis Report for {IMAGE_NAME}</title>
        <style>
            body {{ font-family: Arial, sans-serif; margin: 20px; }}
            h1 {{ color: #333; }}
            h2 {{ color: #555; }}
            pre {{ background-color: #f9f9f9; padding: 10px; border: 1px solid #ddd; }}
        </style>
    </head>
    <body>
        <h1>Memory Image Analysis Report</h1>
        <h2>Report Generated on {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</h2>
    """
    
    # Detect profile
    print("Detecting profile...")
    result = get_profile_detection()
    report_content += "<h2>Profile Detection</h2>"
    if "error" in result:
        report_content += f"<pre>Error: {result['error']}</pre>"
        print(f"Error detecting profile: {result['error']}")
    else:
        profile_detection_file = os.path.join(SCANS_DIR, 'profile_detection.txt')
        save_to_file(profile_detection_file, result['output'])
        report_content += f"<pre>{result['output']}</pre>"
        print(f"Profile detection saved to {profile_detection_file}")

    # List running processes
    print("Listing running processes...")
    result = get_process_list()
    report_content += "<h2>Process List</h2>"
    if "error" in result:
        report_content += f"<pre>Error: {result['error']}</pre>"
        print(f"Error listing processes: {result['error']}")
    else:
        process_list_file = os.path.join(SCANS_DIR, 'process_list.txt')
        save_to_file(process_list_file, result['output'])
        report_content += f"<pre>{result['output']}</pre>"
        print(f"Process list saved to {process_list_file}")

    # List network connections
    print("Listing network connections...")
    result = get_network_connections()
    report_content += "<h2>Network Connections</h2>"
    if "error" in result:
        report_content += f"<pre>Error: {result['error']}</pre>"
        print(f"Error listing network connections: {result['error']}")
    else:
        network_connections_file = os.path.join(SCANS_DIR, 'network_connections.txt')
        save_to_file(network_connections_file, result['output'])
        report_content += f"<pre>{result['output']}</pre>"
        print(f"Network connections saved to {network_connections_file}")

    # Dump registry hives
    print("Dumping registry hives...")
    result = get_registry_hives()
    report_content += "<h2>Registry Hives</h2>"
    if "error" in result:
        report_content += f"<pre>Error: {result['error']}</pre>"
        print(f"Error dumping registry hives: {result['error']}")
    else:
        registry_hives_file = os.path.join(SCANS_DIR, 'registry_hives.txt')
        save_to_file(registry_hives_file, result['output'])
        report_content += f"<pre>{result['output']}</pre>"
        print(f"Registry hives saved to {registry_hives_file}")

    # List user accounts
    print("Listing user accounts...")
    result = get_user_accounts()
    report_content += "<h2>User Accounts</h2>"
    if "error" in result:
        report_content += f"<pre>Error: {result['error']}</pre>"
        print(f"Error listing user accounts: {result['error']}")
    else:
        user_accounts_file = os.path.join(SCANS_DIR, 'user_accounts.txt')
        save_to_file(user_accounts_file, result['output'])
        report_content += f"<pre>{result['output']}</pre>"
        print(f"User accounts saved to {user_accounts_file}")

    # List kernel modules
    print("Listing kernel modules...")
    result = get_kernel_modules()
    report_content += "<h2>Kernel Modules</h2>"
    if "error" in result:
        report_content += f"<pre>Error: {result['error']}</pre>"
        print(f"Error listing kernel modules: {result['error']}")
    else:
        kernel_modules_file = os.path.join(SCANS_DIR, 'kernel_modules.txt')
        save_to_file(kernel_modules_file, result['output'])
        report_content += f"<pre>{result['output']}</pre>"
        print(f"Kernel modules saved to {kernel_modules_file}")

    # Finish HTML report
    report_content += """
    </body>
    </html>
    """
    html_report_file = os.path.join(OUTPUT_DIR, 'analysis_report.html')
    save_to_html(html_report_file, report_content)
    print(f"HTML report generated at {html_report_file}")

if __name__ == "__main__":
    generate_html_report()
