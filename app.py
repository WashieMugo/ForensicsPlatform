from flask import Flask, render_template, redirect, url_for, flash, request, jsonify, send_from_directory, abort
from flask_migrate import Migrate
from models import db, User, UploadedFile, AutoScan, Documentation, FTKActivityLog, FTKOps, VolManual
from forms import RegistrationForm, LoginForm, UploadFileForm, FTKOperationsForm
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from werkzeug.utils import secure_filename
import os
import subprocess
from datetime import datetime
import math
from sqlalchemy import func
from dotenv import load_dotenv
from flask_wtf.csrf import CSRFProtect

from werkzeug.security import generate_password_hash, check_password_hash

import shutil
import time

load_dotenv('dash.env')


# Tool paths and output directories
FTK_TOOL_PATH  = os.getenv("FTK_TOOL_PATH")
FTK_OUTPUT_DIR = os.getenv("FTK_OUTPUT_DIR")
VOL_TOOL_PATH = os.getenv("VOL_TOOL_PATH")
VOL_OUTPUT_DIR = os.getenv("VOL_OUTPUT_DIR")
TSK_TOOL_PATH = os.getenv("TSK_TOOL_PATH")
VOL_OUTPUT_DIR = os.getenv("VOL_OUTPUT_DIR")
TSK_OUTPUT_DIR = os.getenv("TSK_OUTPUT_DIR")

VOL_OUTPUT_MAN = os.getenv("VOL_OUTPUT_MAN")


WHK_PATH = os.getenv("WHK_PATH")
ftk_tool_path = FTK_TOOL_PATH 

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///forensiDB.db'
app.config['SECRET_KEY'] = 'your_secret_key'
csrf = CSRFProtect(app)
db.init_app(app)

migrate = Migrate(app, db)


login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    form = UploadFileForm()

    if request.method == 'POST' and form.validate_on_submit():
        return redirect(url_for('upload_file'))

    # Retrieve the uploaded files for the current user
    uploaded_files = UploadedFile.query.filter_by(user_id=current_user.id).all()

    # Format file size for display and check for existing documentation
    for file in uploaded_files:
        file.size_display = format_file_size(file.size)

        # Retrieve the associated documentation, if it exists
        file.documentation = Documentation.query.filter_by(file_id=file.id).first() or None  # Attach the documentation to the file object

    # Fetch user stats and auto scan reports
    stats = calculate_user_stats(current_user.id)
    autoscans = fetch_autoscans(current_user.id)

    # Prepare auto scan reports for rendering
    auto_scan_reports = []
    for scan, filename in autoscans:
        total_time = (scan.end_time - scan.start_time).total_seconds() / 60  # Total time in minutes
        auto_scan_reports.append({
            'id': scan.id,
            'filename': filename,
            'start_time': scan.start_time,
            'end_time': scan.end_time,
            'total_time': round(total_time, 2)  # Round to 2 decimal places
        })

    return render_template('dashboard.html', 
                           form=form, 
                           uploaded_files=uploaded_files, 
                           stats=stats, 
                           autoscan_reports=auto_scan_reports)


# Utility function to convert bytes to human-readable format
def format_file_size(size_in_bytes):
    if size_in_bytes == 0:
        return "0 B"
    
    size_name = ("B", "KB", "MB", "GB", "TB")
    i = int(math.floor(math.log(size_in_bytes, 1024)))
    p = math.pow(1024, i)
    s = round(size_in_bytes / p, 2)
    return f"{s} {size_name[i]}"

#from werkzeug.security import generate_password_hash, check_password_hash

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        # Check if username already exists
        existing_user = User.query.filter_by(username=form.username.data).first()
        if existing_user:
            flash('Username already exists. Please choose a different one.', 'danger')
            return redirect(url_for('register'))

        # Hash the password before storing it
        hashed_password = generate_password_hash(form.password.data)  # Default is 'pbkdf2:sha256'
        
        # Create a new user with the hashed password
        new_user = User(username=form.username.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        flash('Registration successful! You can now log in.', 'success')
        return redirect(url_for('login'))
    
    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and check_password_hash(user.password, form.password.data):
            login_user(user)
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password. Please try again.', 'danger')
    return render_template('login.html', form=form)

# for volatility manual scanning: 
@app.route('/volatility', methods=['GET', 'POST'])
@login_required
def volatility():
    # Retrieve the uploaded files for the current user
    uploaded_files = UploadedFile.query.filter_by(user_id=current_user.id, file_type='memory').all()
    
    # Retrieve saved files for the current user, ordered by datetime
    saved_files = VolManual.query.filter_by(user_id=current_user.id).order_by(VolManual.date_time.desc()).all()
    
    return render_template('volatility.html', uploaded_files=uploaded_files, saved_files=saved_files)

from flask import jsonify
import logging
logging.basicConfig(level=logging.DEBUG)

@app.route('/get_process_list', methods=['POST'])
@login_required
def get_process_list():
    """Fetches the process list using windows.psscan.PsScan."""
    logging.debug(f"CSRF Token Header: {request.headers.get('X-CSRFToken')}")
    logging.debug(f"Request JSON: {request.json}")
    
    memory_file_name = request.json.get('memory_file')
    if not memory_file_name:
        return jsonify({"error": "Memory file name is required"}), 400

    memory_file = UploadedFile.query.filter_by(filename=memory_file_name, user_id=current_user.id, file_type='memory').first()
    if not memory_file:
        return jsonify({"error": "Memory file not found or unauthorized access."}), 404

    memory_file_path = os.path.join(MEM_DIR, memory_file.filename)
    output = run_volatility_command(memory_file_path, "windows.psscan.PsScan")
    
    if "error" in output:
        return jsonify(output), 500

    process_data = [
        {
            "description": "Scans for processes present in a Windows memory image.",
            "name": "windows.psscan.PsScan",
            "parameters": [
                {"name": "Display physical offsets", "type": "checkbox"},
                {"name": "Process ID", "options": ["wininit.exe (568)", "csrss.exe (584)", "services.exe (712)"], "type": "select"}
            ]
        }
    ]
    return jsonify(process_data)



import subprocess
import json

def run_volatility_command(memory_file, command, params=None):
    """Runs a volatility command and returns the parsed output."""
    try:
        base_cmd = ["python", VOL_TOOL_PATH, "-f", memory_file, command]
        if params:
            base_cmd.extend(params)
        
        # Run command and capture output
        result = subprocess.run(base_cmd, capture_output=True, text=True)
        if result.returncode != 0:
            return {"error": result.stderr.strip()}
        
        return {"output": result.stdout.strip()}
    except Exception as e:
        return {"error": str(e)}

import subprocess

@app.route('/run_command', methods=['POST'])
@login_required
def run_command():
    data = request.json
    file_id = data.get('fileId')
    command = data.get('command')
    parameters = data.get('parameters', {})

    # Validate the memory file
    memory_file = UploadedFile.query.filter_by(id=file_id, user_id=current_user.id, file_type='memory').first()
    if not memory_file:
        return jsonify({'success': False, 'error': 'Memory file not found or unauthorized access.'}), 404

    memory_file_path = os.path.join(MEM_DIR, memory_file.filename)

    # Build the Volatility command
    vol_command = ["python", VOL_TOOL_PATH, "-f", memory_file_path, command]
    for key, value in parameters.items():
        if isinstance(value, bool) and value:  # Checkbox options
            vol_command.append(f"--{key}")
        elif value:  # Non-checkbox options
            vol_command.append(f"--{key}={value}")

    # Execute the command
    try:
        process = subprocess.Popen(vol_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        stdout, stderr = process.communicate()

        if process.returncode == 0:
            return jsonify({'success': True, 'output': stdout})
        else:
            return jsonify({'success': False, 'error': stderr})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})


@app.route('/save_output', methods=['POST'])
@csrf.exempt  # Disable CSRF protection for this route (not recommended)
@login_required
def save_output():
    data = request.json
    file_id = data.get('fileId')
    file_name = data.get('fileName')
    output_content = data.get('output')  # Use the actual output content

    # Ensure the VOL_OUTPUT_MAN environment variable is set
    if not VOL_OUTPUT_MAN:
        return jsonify({'success': False, 'error': 'Output directory is not configured.'}), 500

    # Validate memory file
    memory_file = UploadedFile.query.filter_by(id=file_id, user_id=current_user.id, file_type='memory').first()
    if not memory_file:
        return jsonify({'success': False, 'error': 'Memory file not found or unauthorized access.'}), 404

    # Ensure the directory exists
    if not os.path.exists(VOL_OUTPUT_MAN):
        os.makedirs(VOL_OUTPUT_MAN)

    # Save the output content to a file
    file_path = os.path.join(VOL_OUTPUT_MAN, file_name)

    try:
        with open(file_path, 'w') as f:
            f.write(output_content)

        # Save the record in vol_manual table
        vol_manual = VolManual(user_id=current_user.id, file_id=file_id, file_name=file_name, output=file_path)
        db.session.add(vol_manual)
        db.session.commit()

        return jsonify({'success': True, 'message': 'Output saved successfully!', 'filePath': file_path})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

from flask import send_from_directory

@app.route('/output/<filename>')
def serve_output(filename):
    return send_from_directory(VOL_OUTPUT_MAN, filename)

from flask import Response

@app.route('/view_output/<filename>')
def view_output(filename):
    try:
        # Construct the full file path
        file_path = os.path.join(VOL_OUTPUT_MAN, filename)
        
        # Debugging line to check the full file path
        print(f"Attempting to open file at: {file_path}")

        # Read the content of the file
        with open(file_path, 'r') as file:
            file_content = file.read()

        # Return the content as plain text
        return Response(file_content, mimetype='text/plain')
    
    except Exception as e:
        return f"Error reading file: {str(e)}", 500


    
@app.route('/logout')
@login_required
def logout():
    logout_user()  # This will log out the user
    flash('You have been logged out.', 'info')  # Flash a message
    return redirect(url_for('login'))  # Redirect to the login page

import json
def human_readable_size(size_in_bytes):
    """
    Convert a byte value to a human-readable size (KB, MB, GB).
    """
    for unit in ['bytes', 'KB', 'MB', 'GB', 'TB']:
        if size_in_bytes < 1024.0:
            return f"{size_in_bytes:.2f} {unit}"
        size_in_bytes /= 1024.0
    return f"{size_in_bytes:.2f} PB"

@app.route('/ftk', methods=['GET', 'POST'])
@login_required
def ftk():
    form = FTKOperationsForm()
    logs = FTKOps.query.filter_by(user_id=current_user.id).order_by(FTKOps.timestamp.desc()).all()
    uploaded_files = UploadedFile.query.filter_by(user_id=current_user.id).all()

    # Combine file data with FTKOps data
    files_with_ops = []
    for file in uploaded_files:
        # Find corresponding FTKOps record if it exists
        ftk_op = FTKOps.query.filter_by(file_id=file.id).first()

        # Parse the hash_values field as JSON if it's not None or empty
        hash_values = None
        if ftk_op and ftk_op.hash_values:
            try:
                hash_values = json.loads(ftk_op.hash_values)  # Parse JSON string into dictionary
            except json.JSONDecodeError:
                hash_values = None  # Handle any JSON parsing errors

        # Add a dictionary combining both tables' data
        files_with_ops.append({
            'id': file.id,
            'filename': file.filename,
            'file_type': file.file_type,
            'size': human_readable_size(file.size),
            'verified': file.status,  # Assuming "status" is used for verification
            'hash_values': hash_values,  # Pass parsed hash_values here
            'drive_info': ftk_op.drive_info if ftk_op else None,
            'deleted_files': ftk_op.deleted_files if ftk_op else None,
        })

    return render_template('ftk.html', form=form, logs=logs, files=files_with_ops)







## ---- UPLOAD ------ ##
# Define your base directory
BASE_DIR = 'Files'
MEM_DIR = os.path.join(BASE_DIR, 'mem')
IMAGES_DIR = os.path.join(BASE_DIR, 'images')

# Make sure the directories exist
if not os.path.exists(MEM_DIR):
    os.makedirs(MEM_DIR)
if not os.path.exists(IMAGES_DIR):
    os.makedirs(IMAGES_DIR)

def is_memory_file(file):
    # Check if the file has a specific extension for memory files
    return file.filename.endswith(('.mem', '.dmp', '.raw', '.lks', '.hdd'))  # Adjusted for memory files

def is_os_image_file(file):
    # Check if the file is an OS image (e.g., ISO, IMG, etc.)
    return file.filename.endswith(('.iso', '.img', '.dd', '.E01'))  # Adjusted for OS images

@app.route('/upload', methods=['POST'])
@login_required
def upload_file():
    if 'file' not in request.files:
        flash('No file part')
        return redirect(request.url)

    file = request.files['file']

    if file.filename == '':
        flash('No selected file')
        return redirect(request.url)

    if file:
        filename = secure_filename(file.filename)  # Secure the filename
        file_format = os.path.splitext(filename)[1].lower()  # Get the file extension

        # Validate file types before processing
        if not is_memory_file(file) and not is_os_image_file(file):
            flash('Invalid file type. Only memory files and OS images are allowed!', 'danger')
            return redirect(url_for('dashboard'))

        # Save the file to the appropriate directory
        save_path = os.path.join(MEM_DIR if is_memory_file(file) else IMAGES_DIR, filename)
        file.save(save_path)

        # Get the file size after saving it
        file_size = os.path.getsize(save_path)  # Get file size in bytes from the saved file

        # Insert file details into the database
        uploaded_file = UploadedFile(
            filename=filename,
            file_type='memory' if is_memory_file(file) else 'os_image',
            format=file_format,
            size=file_size,
            user_id=current_user.id,  # Assuming you use Flask-Login for user management
            # doc_exists=False,
        )

        db.session.add(uploaded_file)
        db.session.commit()

        flash(f'File uploaded successfully! Size: {file_size} bytes', 'success')
        return redirect(url_for('dashboard'))  # Redirect to dashboard instead of an additional page

    return redirect(request.url)

@app.route('/delete/<int:file_id>', methods=['POST'])
@login_required
def delete_file(file_id):
    uploaded_file = UploadedFile.query.get(file_id)
    
    if not uploaded_file:
        flash('File not found!', 'danger')
        return redirect(url_for('dashboard'))
        
    try:
        # Delete associated records first
        # Delete metadata if exists
        if uploaded_file.metadata_file_path and os.path.exists(uploaded_file.metadata_file_path):
            os.remove(uploaded_file.metadata_file_path)
            
        # Delete any associated AutoScan records
        auto_scans = AutoScan.query.filter_by(file_id=file_id).all()
        for scan in auto_scans:
            # Delete the report file if it exists
            if scan.report and os.path.exists(scan.report):
                os.remove(scan.report)
            db.session.delete(scan)
            
        # Delete any associated Documentation
        documentation = Documentation.query.filter_by(file_id=file_id).first()
        if documentation:
            db.session.delete(documentation)
            
        # Delete any associated FTKOps
        ftk_ops = FTKOps.query.filter_by(file_id=file_id).all()
        for op in ftk_ops:
            db.session.delete(op)
            
        # Delete the actual file from filesystem
        file_path = os.path.join(
            MEM_DIR if uploaded_file.file_type == 'memory' else IMAGES_DIR, 
            uploaded_file.filename
        )
        if os.path.exists(file_path):
            os.remove(file_path)
            
        # Delete the database record
        db.session.delete(uploaded_file)
        db.session.commit()
        
        flash('File and all associated data deleted successfully!', 'success')
        
    except Exception as e:
        db.session.rollback()
        flash(f'Error deleting file: {str(e)}', 'danger')
        print(f"Error deleting file: {str(e)}")  # For debugging
        
    return redirect(url_for('dashboard'))


from flask_wtf.csrf import validate_csrf
@app.route('/auto_scan/<int:file_id>', methods=['POST'])
@login_required
def auto_scan(file_id):
    try:
        validate_csrf(request.form.get('csrf_token'))
    except Exception as e:
        return jsonify({"error": "CSRF validation failed"}), 400
        
    # Retrieve the file information from the database
    uploaded_file = UploadedFile.query.get(file_id)
    if not uploaded_file:
        return jsonify({"error": "File not found"}), 404

    # Get the path of the file
    file_path = os.path.join(MEM_DIR if uploaded_file.file_type == 'memory' else IMAGES_DIR, uploaded_file.filename)

    # Determine the output directory based on file type
    image_name = os.path.basename(uploaded_file.filename).split('.')[0]

    if uploaded_file.file_type == 'memory':
        # Set output folder for volatility analysis
        VOL_OUTPUT_PATH = os.getenv("VOL_OUTPUT_DIR")
        image_name = os.path.basename(file_path).split('.')[0]
        output_dir = os.path.join(VOL_OUTPUT_PATH, image_name)  # Volatility output folder
        report_path = os.path.join(output_dir, 'analysis_report.html')
        script_path = 'volauto.py'  # Path to Volatility script
    elif uploaded_file.file_type == 'os_image':
        # Set output folder for SleuthKit analysis
        TSK_OUTPUT_DIR = os.getenv("TSK_OUTPUT_DIR")
        image_name = os.path.basename(file_path).split('.')[0]
        output_dir = os.path.join(TSK_OUTPUT_DIR, image_name)  # SleuthKit output folder
        report_path = os.path.join(output_dir, 'analysis_report.html')
        script_path = 'tskauto.py'  # Path to SleuthKit script
    else:
        return jsonify({"error": "Unsupported file type"}), 400

    # Prepare the command for execution
    command = ['python', script_path, file_path]

    # Log the command for testing
    print(f"Running command: {' '.join(command)}")

    # Execute the command
    start_time = datetime.now()  # Capture start time
    try:
        result = subprocess.run(command, check=True, capture_output=True, text=True)
        print(result.stdout)  # Log the output for testing

        # Capture end time
        end_time = datetime.now()

        # Update the uploaded file status
        uploaded_file.status = "AutoScanned"
        db.session.commit()

        # Create a new entry in the autoscans table
        new_scan = AutoScan(
            start_time=start_time,
            end_time=end_time,
            file_id=file_id,
            file_type=uploaded_file.file_type,
            report=report_path,  # Use the determined report path
            user_id=current_user.id  # Add current user's ID
        )
        db.session.add(new_scan)
        db.session.commit()

        # Flash a success message
        flash("Scan completed successfully!", "success")
        return redirect(url_for('dashboard'))  # Redirect to the dashboard page
    except subprocess.CalledProcessError as e:
        print(e.stderr)  # Log any errors for testing
        flash("Failed to start scan", "danger")  # Flash an error message
        return redirect(url_for('dashboard'))  # Redirect to the dashboard page

@app.route('/view_report/<int:report_id>')
@login_required
def view_report(report_id):
    # Fetch the AutoScan record by report_id
    auto_scan = AutoScan.query.get(report_id)

    if auto_scan:
        # Get the directory and file name from the report path
        report_path = auto_scan.report
        report_directory = os.path.dirname(report_path)
        report_filename = os.path.basename(report_path)

        # Serve the HTML report file
        return send_from_directory(report_directory, report_filename)
    else:
        flash('Report not found.', 'danger')
        return redirect(url_for('dashboard'))

@app.route('/view_report2/<int:file_id>')
@login_required
def view_report2(file_id):
    """View report for a file from the uploaded files table."""
    # Fetch the most recent AutoScan record for this file
    auto_scan = AutoScan.query.filter_by(file_id=file_id).order_by(AutoScan.end_time.desc()).first()

    if not auto_scan:
        flash('Report not found.', 'danger')
        return redirect(url_for('dashboard'))

    # Verify the report belongs to the current user
    if auto_scan.user_id != current_user.id:
        flash('Unauthorized access.', 'danger')
        return redirect(url_for('dashboard'))

    try:
        # Get the directory and file name from the report path
        report_path = auto_scan.report
        report_directory = os.path.dirname(report_path)
        report_filename = os.path.basename(report_path)

        # Serve the HTML report file
        return send_from_directory(report_directory, report_filename)
    except Exception as e:
        flash(f'Error viewing report: {str(e)}', 'danger')
        return redirect(url_for('dashboard'))


import json
from flask import jsonify

@app.route('/list_available_drives', methods=['GET'])
def list_available_drives():
    try:
        # Run the FTK Imager command to list drives
        ftk_command = ["ftkimager", "--list-drives"]
        process = subprocess.Popen(ftk_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        stdout, stderr = process.communicate()

        if process.returncode != 0:
            print("Error running ftkimager:", stderr)  # Log any error
            return jsonify({"drives": []})

        # Initialize a list for storing parsed drive information
        drive_list = []

        # Combine stdout and stderr, split into lines
        drive_lines = (stdout + stderr).splitlines()

        for line in drive_lines:
            if '\\\\.\\' in line:  # Check for any drive type (physical, logical, etc.)
                # If the line contains a '-', we assume it's a valid drive
                if ' - ' in line:
                    parts = line.split(' - ')
                    device_id = parts[0].strip()  # Get the device ID
                    description = parts[1].strip() if len(parts) > 1 else "Unknown Drive"  # Get the description

                    # Skip devices that are likely RAM or virtual drives (if needed)
                    if "RAM" in description or "Virtual Disk" in description:
                        continue

                    drive = {
                        "device": device_id,
                        "label": description
                    }
                    drive_list.append(drive)
                else:
                    # Handle the case where there is no separator (likely RAM)
                    device_id = line.strip()
                    # Optionally, decide to include or skip it
                    # For now, we skip drives without a proper separator
                    if "RAM" in device_id:
                        continue  # Skip the RAM drive
                    else:
                        # You can optionally add an unknown label or include it differently
                        drive = {
                            "device": device_id,
                            "label": "Unknown Drive"
                        }
                        drive_list.append(drive)

        # Log the parsed drive list
        print("Drive List:", drive_list)
        return jsonify({"drives": drive_list})
    except Exception as e:
        print("Exception:", e)  # Log any exceptions
        return jsonify({"drives": []})



@app.route('/run_disk_imaging', methods=['POST'])
@login_required
def run_disk_imaging():
    drive = request.form.get('drive')
    image_name = request.form.get('image_name')
    
    # Ensure the output directory exists
    output_path = os.path.join(FTK_OUTPUT_DIR, f"{current_user.username}_{image_name}")
    if not os.path.exists(output_path):
        os.makedirs(output_path)
    
    # Add .E01 extension to the output file path since FTK Imager will add it automatically
    output_file = os.path.join(output_path, f"{image_name}")
    final_output_file = f"{output_file}.E01"

    try:
        # Debug: print paths to ensure they are correct
        print(f"FTK Output Directory: {output_path}")
        print(f"FTK Output File: {output_file}")
        print(f"Final Output File (with E01): {final_output_file}")

        # Run the FTK Imager command
        subprocess.run(['ftkimager', drive, output_file, '--e01', '--compress', '1'], check=True)

        # Wait briefly to ensure the file is fully written
        time.sleep(2)

        # Get the file size of the created .E01 file
        if os.path.exists(final_output_file):
            file_size = os.path.getsize(final_output_file)
        else:
            raise FileNotFoundError(f"Expected image file not found: {final_output_file}")

        # Determine the directory (MEM_DIR or IMAGES_DIR) based on file type
        save_dir = IMAGES_DIR  # Since disk images are always OS images

        # Create the final destination path with .E01 extension
        final_destination = os.path.join(save_dir, f"{image_name}.E01")

        # Move the image to the appropriate directory
        shutil.move(final_output_file, final_destination)

        # Insert file details into the database
        uploaded_file = UploadedFile(
            filename=f"{image_name}.E01",  # Include the .E01 extension
            file_type='os_image',
            format='.E01',
            size=file_size,
            user_id=current_user.id,
            ftk_imaged=True
        )
        db.session.add(uploaded_file)
        db.session.commit()

        # Add FTK operation record
        ftk_op = FTKOps(
            user_id=current_user.id,
            file_id=uploaded_file.id,
            operation='create_disk_image',  # This field should now be recognized
            status='Completed',
            timestamp=datetime.utcnow()
        )
        db.session.add(ftk_op)
        db.session.commit()

        flash('Imaging successfully completed and uploaded!', 'success')
        return redirect(url_for('ftk'))

    except Exception as e:
        flash(f'Failed to create disk image: {str(e)}', 'danger')
        return redirect(url_for('ftk'))



from sqlalchemy import func

def calculate_user_stats(user_id):
    # Total files uploaded by user
    total_files = UploadedFile.query.filter_by(user_id=user_id).count()

    # Memory and OS image files breakdown
    memory_files = UploadedFile.query.filter_by(user_id=user_id, file_type='memory').count()
    os_image_files = UploadedFile.query.filter_by(user_id=user_id, file_type='os_image').count()

    # Total scans performed (from AutoScan)
    total_scans = AutoScan.query.filter_by(user_id=user_id).count()

    # Total report files (assuming each AutoScan has one report)
    total_reports = AutoScan.query.filter_by(user_id=user_id).count()

    # Total storage size (sum of file sizes uploaded by the user)
    total_storage = db.session.query(func.sum(UploadedFile.size)).filter_by(user_id=user_id).scalar() or 0

    # Storage for memory files and OS image files separately
    memory_storage = db.session.query(func.sum(UploadedFile.size)).filter_by(user_id=user_id, file_type='memory').scalar() or 0
    os_image_storage = db.session.query(func.sum(UploadedFile.size)).filter_by(user_id=user_id, file_type='os_image').scalar() or 0

    return {
        "total_files": total_files,
        "memory_files": memory_files,
        "os_image_files": os_image_files,
        "total_scans": total_scans,
        "total_reports": total_reports,
        "total_storage": total_storage,
        "memory_storage": memory_storage,  # New: Total size of memory files
        "os_image_storage": os_image_storage  # New: Total size of OS image files
    }


def fetch_autoscans(user_id):
    # Fetch all auto scan reports for the user along with the corresponding file name
    return (
        db.session.query(AutoScan, UploadedFile.filename)
        .join(UploadedFile, AutoScan.file_id == UploadedFile.id)
        .filter(AutoScan.user_id == user_id)
        .all()
    )

@app.route('/add-documentation/<int:file_id>', methods=['GET', 'POST'])
def add_documentation(file_id):
    uploaded_file = UploadedFile.query.get(file_id)  # Get the uploaded file object

    if request.method == 'POST':
        # Get data from the form
        case_number = request.form.get('case_number')
        investigator_email = request.form.get('investigator_email')
        purpose = request.form.get('purpose')
        option1 = 'option1' in request.form
        option2 = 'option2' in request.form
        option3 = 'option3' in request.form

        # Check if documentation already exists
        documentation = Documentation.query.filter_by(file_id=file_id).first()

        if documentation:
            # Update existing documentation
            documentation.case_number = case_number
            documentation.investigator_email = investigator_email
            documentation.purpose = purpose
            documentation.option1 = option1
            documentation.option2 = option2
            documentation.option3 = option3
            documentation.last_updated = datetime.utcnow()
        else:
            # Add new documentation
            new_doc = Documentation(
                file_id=file_id, case_number=case_number,
                investigator_email=investigator_email, purpose=purpose,
                option1=option1, option2=option2, option3=option3
            )
            db.session.add(new_doc)

        # Update doc_exists to True if documentation is added or updated
        uploaded_file.doc_exists = True

        # Commit all changes (for both Documentation and UploadedFile)
        db.session.commit()

        flash('Documentation saved successfully', 'success')
        return redirect(url_for('dashboard'))

    # GET request: Load existing documentation if any
    documentation = Documentation.query.filter_by(file_id=file_id).first()

    return render_template('add_documentation.html', file_id=file_id, documentation=documentation)


# -------- FETCH METADATA -----------------------
from volmeta import fetch_memory_metadata
from stkmeta import fetch_image_metadata
import os
from flask import jsonify

import os
import json

@app.route('/fetch_metadata/<int:file_id>', methods=['POST'])
@login_required
def fetch_metadata(file_id):
    """Fetch metadata for the uploaded file based on its type."""
    uploaded_file = UploadedFile.query.get(file_id)
    if not uploaded_file:
        flash('File not found', 'danger')
        return jsonify({"error": "File not found"}), 404

    try:
        # Get the path of the file
        file_path = os.path.join(MEM_DIR if uploaded_file.file_type == 'memory' else IMAGES_DIR, uploaded_file.filename)
        output_dir = os.getenv('VOL_OUTPUT_DIR' if uploaded_file.file_type == 'memory' else 'TSK_OUTPUT_DIR')

        # Initialize metadata variable
        metadata = {}

        if uploaded_file.file_type == 'memory':
            metadata = fetch_memory_metadata(file_path, output_dir)
        elif uploaded_file.file_type == 'os_image':
            metadata = fetch_image_metadata(file_path, output_dir)
        else:
            flash('Unsupported file type', 'danger')
            return jsonify({"error": "Unsupported file type"}), 400

        # Save metadata to a JSON file
        metadata_file_path = os.path.join(output_dir, f'{uploaded_file.filename}_metadata.json')
        with open(metadata_file_path, 'w') as json_file:
            json.dump(metadata, json_file)

        # Update the uploaded file record
        uploaded_file.has_metadata = True
        uploaded_file.metadata_file_path = metadata_file_path
        db.session.commit()

        flash('Metadata fetched successfully!', 'success')
        return jsonify({"message": "Metadata fetched successfully"}), 200

    except Exception as e:
        flash(f'Error fetching metadata: {str(e)}', 'danger')
        return jsonify({"error": str(e)}), 500

@app.route('/view_metadata/<int:file_id>', methods=['GET'])
@login_required
def view_metadata(file_id):
    """View metadata for the uploaded file."""
    uploaded_file = UploadedFile.query.get(file_id)
    if not uploaded_file or not uploaded_file.metadata_file_path:
        return jsonify({"error": "Metadata not found"}), 404

    # Load the metadata from the JSON file
    with open(uploaded_file.metadata_file_path, 'r') as json_file:
        metadata = json.load(json_file)

    # Process metadata to show top 5 entries where necessary
    limited_metadata = {}
    for key, value in metadata.items():
        if isinstance(value, list) and len(value) > 5:
            limited_metadata[key] = value[:5]  # Show only the top 5
            limited_metadata[f"{key}_truncated"] = True  # Mark as truncated
        else:
            limited_metadata[key] = value

        # Convert objects in the lists to a more readable format (customize as needed)
        if isinstance(value, list):
            for index in range(len(limited_metadata[key])):
                if isinstance(limited_metadata[key][index], dict):
                    # Convert the object to a string representation, e.g., join specific fields
                    limited_metadata[key][index] = ", ".join(f"{k}: {v}" for k, v in limited_metadata[key][index].items() if k != "other_field")

    return jsonify({"metadata": limited_metadata, "file_id": file_id}), 200

import json
import pprint  # This will help print the metadata in a readable format

@app.route('/view_full_metadata/<int:file_id>', methods=['GET'])
@login_required
def view_full_metadata(file_id):
    """View full metadata for the uploaded file."""
    uploaded_file = UploadedFile.query.get(file_id)
    if not uploaded_file or not uploaded_file.metadata_file_path:
        return "Metadata not found", 404

    # Load the metadata from the JSON file
    with open(uploaded_file.metadata_file_path, 'r') as json_file:
        metadata = json.load(json_file)

    # Log the metadata for debugging purposes
   # pprint.pprint(metadata)

    return render_template('view_full_metadata.html', metadata=metadata, filename=uploaded_file.filename)


# DOWNLOAD REPORT: @app.route('/download_report/<int:report_id>')
import os
from flask import send_file, abort, make_response
import pdfkit

# Retrieve the path to wkhtmltopdf from environment variables
WHK_PATH = os.getenv("WHK_PATH")

# Check if the path is set correctly
if not WHK_PATH:
    raise ValueError("WHK_PATH is not set in the environment variables.")

# Specify the path to wkhtmltopdf.exe
pdfkit_config = pdfkit.configuration(wkhtmltopdf=WHK_PATH)

@app.route('/download_report/<int:report_id>')
def download_report(report_id):
    report = AutoScan.query.get(report_id)
    if report:
        report_path = report.report
        if os.path.exists(report_path):
            try:
                # Use the configuration here
                pdf = pdfkit.from_file(report_path, False, configuration=pdfkit_config)
                
                response = make_response(pdf)
                response.headers['Content-Type'] = 'application/pdf'
                response.headers['Content-Disposition'] = f'attachment; filename=report_{report_id}.pdf'

                return response
            except Exception as e:
                abort(500, description=f"Failed to generate PDF: {str(e)}")
        else:
            abort(404, description="Report not found")
    else:
        abort(404, description="Report not found")


# FTK FETCH HASHES

import re
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
    
    return hash_info


def run_ftkimager_verify(file_path):
    """
    Function to run the FTK Imager verify command and return the output.
    """
    try:
        # Make sure the FTK Imager command is available in your system PATH or specify the full path
        result = subprocess.run(
            ['ftkimager', '--verify', file_path],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=True
        )
        return result.stdout
    except subprocess.CalledProcessError as e:
        print(f"Error running FTK Imager: {e}")
        return None



@app.route('/verify_file/<int:file_id>', methods=['POST'])
@login_required
def verify_file(file_id):
    # Print the file_id for debugging purposes
    print(f"Received request to verify file with ID: {file_id}")
    
    # Look up the file record using file_id
    file_record = UploadedFile.query.get(file_id)
    
    if not file_record:
        flash('File not found', 'danger')
        return redirect(url_for('ftk'))  # Redirect back to the FTK page if the file doesn't exist
    
    try:
        # Determine the file's path based on its type
        file_path = os.path.join(MEM_DIR, file_record.filename) if is_memory_file(file_record) else os.path.join(IMAGES_DIR, file_record.filename)
        
        # Run FTK Imager verification (this function should return the output)
        ftk_output = run_ftkimager_verify(file_path)

        if not ftk_output:
            flash('Error running FTK Imager', 'danger')
            return redirect(url_for('ftk'))  # Redirect back to the FTK page if there is an error
        
        # Extract hash values from FTK output (this function should handle extraction)
        hash_info = extract_hashes_and_info(ftk_output)

        # Insert/update hash values in the database
        existing_ftk_ops = FTKOps.query.filter_by(file_id=file_id).first()
        if existing_ftk_ops:
            existing_ftk_ops.hash_values = json.dumps(hash_info)
        else:
            new_ftk_ops = FTKOps(user_id=current_user.id, file_id=file_id, hash_values=json.dumps(hash_info))
            db.session.add(new_ftk_ops)

        db.session.commit()

        # Flash success message
        flash('Verification successful! Hashes have been saved.', 'success')

    except Exception as e:
        print(f"Error during FTK verification: {e}")
        flash(f"Error: {e}", 'danger')  # Flash error message if any exception occurs
    
    # Redirect back to the FTK page after the process is done
    return redirect(url_for('ftk'))

# Function to run FTK Imager and retrieve drive information
def run_ftkimager_getinfo(file_path):
    """
    FTK function to retrieve drive information.
    """
    try:
        # Ensure the FTK Imager command is available or use the full executable path
        result = subprocess.run(
            ['ftkimager', '--print-info', file_path],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=True
        )
        return result.stdout
    except subprocess.CalledProcessError as e:
        print(f"Error running FTK Imager: {e.stderr}")
        return None


# Flask route to fetch drive information
@app.route('/get_drive_info/<int:file_id>', methods=['POST'])
@login_required
def get_drive_info(file_id):
    print("FTK: ----- Fetching drive information ------")

    # Look up the file record using file_id
    file_record = UploadedFile.query.get(file_id)
    
    if not file_record:
        flash('File not found', 'danger')
        return redirect(url_for('ftk'))

    try:
        # Determine the file's path
        file_path = os.path.join(MEM_DIR, file_record.filename) if is_memory_file(file_record) else os.path.join(IMAGES_DIR, file_record.filename)
        
        # Run FTK Imager command to get drive info
        ftk_output = run_ftkimager_getinfo(file_path)

        if not ftk_output:
            flash('Error running FTK Imager', 'danger')
            return redirect(url_for('ftk'))

        # Save the output to the database or process further
        existing_ftk_ops = FTKOps.query.filter_by(file_id=file_id).first()
        if existing_ftk_ops:
            existing_ftk_ops.drive_info = ftk_output
        else:
            new_ftk_ops = FTKOps(user_id=current_user.id, file_id=file_id, drive_info=ftk_output)
            db.session.add(new_ftk_ops)
        
        db.session.commit()

        # Flash success message
        flash('Drive information fetched successfully.', 'success')

    except Exception as e:
        print(f"Error fetching drive information: {e}")
        flash(f"Error: {e}", 'danger')

    return redirect(url_for('ftk'))

# Function to run FTK Imager and check for deleted files
def run_ftkimager_deletedfiles(file_path):
    """
    FTK function to check for deleted files.
    """
    try:
        result = subprocess.run(
            ['ftkimager', '--list-deleted-files', file_path],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=True
        )
        return result.stdout
    except subprocess.CalledProcessError as e:
        print(f"Error running FTK Imager: {e.stderr}")
        return None


# Flask route to check for deleted files
@app.route('/check_deleted_files/<int:file_id>', methods=['POST'])
@login_required
def check_deleted_files(file_id):
    print("FTK: ----- Checking for deleted files ------")

    # Look up the file record using file_id
    file_record = UploadedFile.query.get(file_id)
    
    if not file_record:
        flash('File not found', 'danger')
        return redirect(url_for('ftk'))

    try:
        # Determine the file's path
        file_path = os.path.join(MEM_DIR, file_record.filename) if is_memory_file(file_record) else os.path.join(IMAGES_DIR, file_record.filename)
        
        # Run FTK Imager command to list deleted files
        ftk_output = run_ftkimager_deletedfiles(file_path)

        if not ftk_output:
            flash('Error running FTK Imager', 'danger')
            return redirect(url_for('ftk'))

        # Save the deleted file records into the database for the file
        existing_ftk_ops = FTKOps.query.filter_by(file_id=file_id).first()
        if existing_ftk_ops:
            existing_ftk_ops.deleted_files = ftk_output
        else:
            new_ftk_ops = FTKOps(user_id=current_user.id, file_id=file_id, deleted_files=ftk_output)
            db.session.add(new_ftk_ops)
        
        db.session.commit()

        # Flash success message
        flash('Deleted files fetched successfully.', 'success')

    except Exception as e:
        print(f"Error fetching deleted files: {e}")
        flash(f"Error: {e}", 'danger')

    return redirect(url_for('ftk'))

# Add this near the top of app.py with other route imports
from flask import url_for, flash, redirect, send_from_directory

# Make sure this route is defined BEFORE any templates that use url_for('delete_report')
@app.route('/delete_report/<int:report_id>', methods=['POST'])
@login_required
def delete_report(report_id):
    """Delete an auto scan report and update associated file status."""
    try:
        # Get the report
        report = AutoScan.query.get(report_id)
        if not report:
            flash('Report not found.', 'danger')
            return redirect(url_for('dashboard'))

        # Verify the report belongs to the current user
        if report.user_id != current_user.id:
            flash('Unauthorized access.', 'danger')
            return redirect(url_for('dashboard'))

        # Get the associated file
        file = UploadedFile.query.get(report.file_id)

        # Delete the physical report file if it exists
        if report.report and os.path.exists(report.report):
            try:
                os.remove(report.report)
            except OSError as e:
                print(f"Error removing file: {e}")  # Log the error but continue

        # Delete the report record from the database
        db.session.delete(report)

        # Update the file status if this was the only report for this file
        remaining_reports = AutoScan.query.filter_by(file_id=file.id).filter(AutoScan.id != report_id).first()
        if file and not remaining_reports:
            file.status = 'Unscanned'  # Reset status to unscanned

        db.session.commit()
        flash('Report deleted successfully.', 'success')

    except Exception as e:
        db.session.rollback()
        flash(f'Error deleting report: {str(e)}', 'danger')
        print(f"Error deleting report: {str(e)}")  # For debugging

    return redirect(url_for('dashboard'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
