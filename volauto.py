import os
import subprocess
import datetime
import sys
from dotenv import load_dotenv

# Load environment variables from dash.env
load_dotenv('dash.env')

# Paths from environment variables
VOL_TOOL_PATH = os.getenv("VOL_TOOL_PATH")
VOL_OUTPUT_PATH = os.getenv("VOL_OUTPUT_DIR")

# Function to run shell commands
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

def get_profile_detection(image_path):
    """Detect the profile of the memory image."""
    command = f'python "{VOL_TOOL_PATH}" -f "{image_path}" windows.info'
    return run_command(command)

def get_process_list(image_path):
    """List running processes."""
    command = f'python "{VOL_TOOL_PATH}" -f "{image_path}" windows.pslist'
    return run_command(command)

def get_network_connections(image_path):
    """List network connections."""
    command = f'python "{VOL_TOOL_PATH}" -f "{image_path}" windows.netscan'
    return run_command(command)

def get_registry_hives(image_path):
    """Dump registry hives."""
    command = f'python "{VOL_TOOL_PATH}" -f "{image_path}" windows.registry.hivelist.HiveList'
    return run_command(command)

def get_user_accounts(image_path):
    """List user accounts."""
    command = f'python "{VOL_TOOL_PATH}" -f "{image_path}" windows.hashdump.Hashdump'
    return run_command(command)

def get_kernel_modules(image_path):
    """List kernel modules."""
    command = f'python "{VOL_TOOL_PATH}" -f "{image_path}" windows.modules'
    return run_command(command)

def generate_html_report(image_path):
    """Generate an HTML report of the analysis."""
    # Extract the base name of the image file (without extension)
    image_name = os.path.basename(image_path).split('.')[0]
    output_dir = os.path.join(VOL_OUTPUT_PATH, image_name)
    scans_dir = os.path.join(output_dir, "scans")

    # Create the necessary directories
    os.makedirs(scans_dir, exist_ok=True)
    
    print(f"Directories created:\nOutput Directory: {output_dir}\nScans Directory: {scans_dir}")
    print("Starting report generation...")
    report_content = f"""
    <html>
    <head>
        <title>Volatility Analysis Report for {image_name}</title>
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
    result = get_profile_detection(image_path)
    report_content += "<h2>Profile Detection</h2>"
    if "error" in result:
        report_content += f"<pre>Error: {result['error']}</pre>"
        print(f"Error detecting profile: {result['error']}")
    else:
        profile_detection_file = os.path.join(scans_dir, 'profile_detection.txt')
        save_to_file(profile_detection_file, result['output'])
        report_content += f"<pre>{result['output']}</pre>"
        print(f"Profile detection saved to {profile_detection_file}")

    # List running processes
    print("Listing running processes...")
    result = get_process_list(image_path)
    report_content += "<h2>Process List</h2>"
    if "error" in result:
        report_content += f"<pre>Error: {result['error']}</pre>"
        print(f"Error listing processes: {result['error']}")
    else:
        process_list_file = os.path.join(scans_dir, 'process_list.txt')
        save_to_file(process_list_file, result['output'])
        report_content += f"<pre>{result['output']}</pre>"
        print(f"Process list saved to {process_list_file}")

    # List network connections
    print("Listing network connections...")
    result = get_network_connections(image_path)
    report_content += "<h2>Network Connections</h2>"
    if "error" in result:
        report_content += f"<pre>Error: {result['error']}</pre>"
        print(f"Error listing network connections: {result['error']}")
    else:
        network_connections_file = os.path.join(scans_dir, 'network_connections.txt')
        save_to_file(network_connections_file, result['output'])
        report_content += f"<pre>{result['output']}</pre>"
        print(f"Network connections saved to {network_connections_file}")

    # Dump registry hives
    print("Dumping registry hives...")
    result = get_registry_hives(image_path)
    report_content += "<h2>Registry Hives</h2>"
    if "error" in result:
        report_content += f"<pre>Error: {result['error']}</pre>"
        print(f"Error dumping registry hives: {result['error']}")
    else:
        registry_hives_file = os.path.join(scans_dir, 'registry_hives.txt')
        save_to_file(registry_hives_file, result['output'])
        report_content += f"<pre>{result['output']}</pre>"
        print(f"Registry hives saved to {registry_hives_file}")

    # List user accounts
    print("Listing user accounts...")
    result = get_user_accounts(image_path)
    report_content += "<h2>User Accounts</h2>"
    if "error" in result:
        report_content += f"<pre>Error: {result['error']}</pre>"
        print(f"Error listing user accounts: {result['error']}")
    else:
        user_accounts_file = os.path.join(scans_dir, 'user_accounts.txt')
        save_to_file(user_accounts_file, result['output'])
        report_content += f"<pre>{result['output']}</pre>"
        print(f"User accounts saved to {user_accounts_file}")

    # List kernel modules
    print("Listing kernel modules...")
    result = get_kernel_modules(image_path)
    report_content += "<h2>Kernel Modules</h2>"
    if "error" in result:
        report_content += f"<pre>Error: {result['error']}</pre>"
        print(f"Error listing kernel modules: {result['error']}")
    else:
        kernel_modules_file = os.path.join(scans_dir, 'kernel_modules.txt')
        save_to_file(kernel_modules_file, result['output'])
        report_content += f"<pre>{result['output']}</pre>"
        print(f"Kernel modules saved to {kernel_modules_file}")

    # Finish HTML report
    report_content += """
    </body>
    </html>
    """
    html_report_file = os.path.join(output_dir, 'analysis_report.html')
    save_to_html(html_report_file, report_content)
    print(f"HTML report generated at {html_report_file}")

# Main execution flow
if __name__ == "__main__":
    # Check for image path argument
    if len(sys.argv) != 2:
        print("Usage: python volauto.py <image_path>")
        sys.exit(1)
    
    image_path = sys.argv[1]  # Get the image path from command-line arguments
    print("Starting Volatility analysis...")
    generate_html_report(image_path)
    print("Volatility analysis completed.")
