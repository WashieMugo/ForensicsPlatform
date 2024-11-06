import subprocess
import json
import os

# JSON file path
json_file_path = 'drives.json'

def list_drives():
    # Command to list drives using FTK Imager
    ftk_command = ["ftkimager", "--list-drives"]
    
    try:
        # Run the FTK Imager command and capture both stdout and stderr
        process = subprocess.Popen(ftk_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        stdout, stderr = process.communicate()

        # Print the raw stdout and stderr for debugging
        print("STDOUT:")
        print(stdout)
        print("STDERR:")
        print(stderr)

        # Combine stdout and stderr
        combined_output = stdout + stderr
        print("Combined Output:")
        print(combined_output)

        if process.returncode != 0:
            print(f"Command failed with return code {process.returncode}")
            return

        # Initialize a list for storing parsed drive information
        drives = []

        # Split combined output into lines
        drive_lines = combined_output.splitlines()
        print("Drive lines extracted from output:", repr(drive_lines))  # Debugging: show raw line content

        for line in drive_lines:
            # Print the line before parsing to check for issues
            print(f"Line before parsing: {repr(line)}")  # Debugging: check line content
            
            # Check if line contains a valid drive ID (detects '\\.\')
            if '\\\\.\\' in line:
                print(f"Parsing line: {line}")  # Debugging: show each line being parsed
                
                # Split the line at ' - ' to get ID and description, if applicable
                parts = line.split(' - ')
                drive_id = parts[0].strip()  # Always get the drive ID
                # Default description if none exists
                drive_description = parts[1].strip() if len(parts) > 1 else "No description available"

                drives.append({"id": drive_id, "description": drive_description})

        # Print parsed drive list for verification
        print("Parsed Drives:")
        print(drives)

        # Save drives to JSON file
        drive_data = {"drives": drives}
        with open(json_file_path, "w") as f:
            json.dump(drive_data, f, indent=4)
        
        print(f"Drive data saved to {json_file_path}")

    except Exception as e:
        print("An unexpected error occurred while executing the command.")
        print(str(e))

if __name__ == "__main__":
    # Confirm the directory where the script is running
    print(f"Running drive listing in {os.getcwd()}")
    list_drives()
