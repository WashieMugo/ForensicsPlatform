import subprocess
import re
import json
import os

def extract_hashes_and_info(ftk_output):
    """
    Function to extract MD5 and SHA1 hashes and associated key-value pairs from FTK Imager output.
    Returns a dictionary containing the extracted data in JSON format.
    """
    hash_info = {"MD5": [], "SHA1": []}
    
    # Define a regular expression to find the lines containing the hash information
    hash_regex = re.compile(r"\[([A-Za-z0-9]+)\](.*?)(?=\[|$)", re.DOTALL)
    match = hash_regex.findall(ftk_output)
    
    # Iterate over MD5 and SHA1 blocks
    for hash_type, block in match:
        hash_type = hash_type.strip()  # MD5 or SHA1
        key_value_pairs = {}
        
        # Look for all key-value pairs in the block after the hash type tag
        pairs = re.findall(r"(\S[\w\s]+?):\s*(.*?)\s*(?=\n|$)", block.strip())
        
        # For each key-value pair, store it in a dictionary
        for key, value in pairs:
            key_value_pairs[key.strip()] = value.strip()
        
        # Append the results to the corresponding hash type
        if hash_type in hash_info:
            hash_info[hash_type].append(key_value_pairs)
    
    return json.dumps(hash_info, indent=4)


def run_ftkimager_verify(file_path):
    """
    Function to run the FTK Imager verify command and return the output.
    """
    try:
        # Make sure the FTK Imager command is available in your system PATH or specify the full path
        # Update 'ftkimager' with the actual path to the FTK Imager executable if necessary
        result = subprocess.run(
            ['ftkimager', '--verify', file_path],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=True
        )
        return result.stdout
    except subprocess.CalledProcessError as e:
        print(f"Error running FTK Imager: {e}")
        return None


def save_to_json(result, output_file):
    """
    Function to save the extracted result to a JSON file.
    """
    try:
        with open(output_file, 'w', encoding='utf-8') as json_file:
            json_file.write(result)
    except Exception as e:
        return str(e)


def process_file(file_path):
    """
    Function to process the FTK Imager output and return the extracted hashes and info as JSON.
    """
    try:
        # Run FTK Imager --verify command on the file
        ftk_output = run_ftkimager_verify(file_path)
        
        if ftk_output is None:
            print(f"Failed to process the file: {file_path}")
            return None
        
        # Extract hashes and info from the FTK Imager output
        result = extract_hashes_and_info(ftk_output)
        return result
    except Exception as e:
        return str(e)


def main():
    # Example paths to FTK Imager output files (Replace these with the actual file paths)
    files = [
        "D:\\WORK\\1 Abdulrhman\\Forensics Platform\\Files\\images\\2020JimmyWilson.E01",
        "D:\\WORK\\1 Abdulrhman\\Forensics Platform\\Files\\images\\extparttest2.dd",
        "D:\\WORK\\1 Abdulrhman\\Forensics Platform\\Files\\mem\\Win10memdump.mem"
    ]
    
    for file_path in files:
        print(f"Processing: {file_path}")
        result = process_file(file_path)
        
        if result:
            # Define the output JSON file name based on the input file name
            output_file = file_path.replace("\\", "_").replace(":", "") + "_hashes.json"
            
            # Save the result to a JSON file
            save_to_json(result, output_file)
            print(f"Results saved to: {output_file}")
        else:
            print(f"Failed to extract data from {file_path}")


if __name__ == "__main__":
    main()
