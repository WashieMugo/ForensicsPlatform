import os
import subprocess
import datetime

# Define FTK Imager CLI path
FTK_IMAGER_CLI_PATH = "C:\\Path\\To\\FTK\\ImagerCLI.exe"

# Function to create a forensic image
def create_forensic_image(source_drive, destination_folder):
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    image_file = os.path.join(destination_folder, f"forensic_image_{timestamp}.E01")
    
    # Command to create forensic image
    command = [
        FTK_IMAGER_CLI_PATH,
        source_drive,
        image_file,
        "/verify",  # Option to verify the image after creation
        "/hash",    # Generate hash values (MD5, SHA1, etc.)
    ]
    
    print(f"Creating forensic image for {source_drive}...")
    try:
        subprocess.run(command, check=True)
        print(f"Forensic image created: {image_file}")
    except subprocess.CalledProcessError as e:
        print(f"Error creating forensic image: {e}")

# Function to verify an existing image
def verify_forensic_image(image_file):
    command = [
        FTK_IMAGER_CLI_PATH,
        "/verify",
        image_file
    ]
    
    print(f"Verifying forensic image: {image_file}...")
    try:
        subprocess.run(command, check=True)
        print("Image verification completed successfully.")
    except subprocess.CalledProcessError as e:
        print(f"Error verifying forensic image: {e}")

# Function to extract specific file types from an image
def extract_files_from_image(image_file, file_type, destination_folder):
    command = [
        FTK_IMAGER_CLI_PATH,
        image_file,
        "/extractFiles",
        destination_folder,
        f"/filetypes:{file_type}"
    ]
    
    print(f"Extracting {file_type} files from image: {image_file}...")
    try:
        subprocess.run(command, check=True)
        print(f"{file_type} files extracted successfully to {destination_folder}.")
    except subprocess.CalledProcessError as e:
        print(f"Error extracting files: {e}")

# Function to automate batch imaging tasks
def batch_process_imaging(drives, destination_folder):
    for drive in drives:
        create_forensic_image(drive, destination_folder)

# Main script function
def main():
    # Example parameters for automation
    source_drive = "\\\\.\\PhysicalDrive0"  # Replace with the correct drive
    destination_folder = "C:\\Forensic_Images"
    image_file = os.path.join(destination_folder, "forensic_image_20230821.E01")
    file_type = "pdf"  # Specify the file type to extract (e.g., "pdf", "jpg")
    
    # Create forensic image
    create_forensic_image(source_drive, destination_folder)
    
    # Verify forensic image
    verify_forensic_image(image_file)
    
    # Extract specific files
    extract_files_from_image(image_file, file_type, destination_folder)

    # Example of batch processing multiple drives
    # drives = ["\\\\.\\PhysicalDrive0", "\\\\.\\PhysicalDrive1"]
    # batch_process_imaging(drives, destination_folder)

if __name__ == "__main__":
    main()
