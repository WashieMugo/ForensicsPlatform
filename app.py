from flask import Flask, render_template, redirect, url_for, flash, request, jsonify, send_from_directory, abort
from flask_migrate import Migrate
from models import db, User, UploadedFile, AutoScan, Documentation, FTKActivityLog, FTKOps
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

load_dotenv('dash.env')


# Tool paths and output directories
FTK_TOOL_PATH  = os.getenv("FTK_TOOL_PATH")
ftk_output_dir = os.getenv("FTK_OUTPUT_DIR")
VOL_TOOL_PATH = os.getenv("VOL_TOOL_PATH")
VOL_OUTPUT_DIR = os.getenv("VOL_OUTPUT_DIR")
TSK_TOOL_PATH = os.getenv("TSK_TOOL_PATH")
TSK_OUTPUT_DIR = os.getenv("TSK_OUTPUT_DIR")
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

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        # Check if username already exists
        existing_user = User.query.filter_by(username=form.username.data).first()
        if existing_user:
            flash('Username already exists. Please choose a different one.', 'danger')
            return redirect(url_for('register'))

        # If the username is unique, create a new user
        new_user = User(username=form.username.data, password=form.password.data)
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
        if user and user.password == form.password.data:
            login_user(user)
            return redirect(url_for('dashboard'))
    return render_template('login.html', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()  # This will log out the user
    flash('You have been logged out.', 'info')  # Flash a message
    return redirect(url_for('login'))  # Redirect to the login page


@app.route('/ftk', methods=['GET', 'POST'])
@login_required
def ftk():
    form = FTKOperationsForm()
    logs = FTKOps.query.filter_by(user_id=current_user.id).order_by(FTKOps.timestamp.desc()).all()
    uploaded_files = UploadedFile.query.filter_by(user_id=current_user.id).all()

    if form.validate_on_submit():
        operation = form.operation.data
        status = "Success"
        selected_file_id = request.form.get("file_id")
        try:
            if operation == "create_disk_image":
                # Step 1: List available drives (simulated here)
                available_drives = ["C:", "D:", "E:"]  # In practice, you'd dynamically list actual drives.
                selected_drive = request.form.get("drive")

                if selected_drive:
                    image_folder = os.path.join(ftk_output_dir, f"{current_user.username}_{selected_drive}_image")
                    os.makedirs(image_folder, exist_ok=True)
                    output_path = os.path.join(image_folder, f"{selected_drive}_disk_image.img")
                    subprocess.run([ftk_tool_path, '--create-image', selected_drive, output_path], check=True)

                    # Add the newly created image to UploadedFile table
                    new_file = UploadedFile(
                        filename=f"{selected_drive}_disk_image.img",
                        file_type="os_image",
                        format=".img",
                        size=os.path.getsize(output_path),
                        user_id=current_user.id
                    )
                    db.session.add(new_file)
                    db.session.commit()

                    # Log the FTK operation with the new file ID
                    new_ftk_op = FTKOps(
                        operation=operation,
                        status=status,
                        user_id=current_user.id,
                        file_id=new_file.id
                    )
                    db.session.add(new_ftk_op)
                    db.session.commit()

            elif operation == "verify_image":
                # Assume we use a sample verify command for demonstration
                selected_file = UploadedFile.query.get(selected_file_id)
                if selected_file:
                    subprocess.run([ftk_tool_path, '--verify', os.path.join(IMAGES_DIR, selected_file.filename)], check=True)

            elif operation == "extract_deleted_files":
                selected_file = UploadedFile.query.get(selected_file_id)
                if selected_file:
                    output_dir = os.path.join(ftk_output_dir, f"{current_user.username}_deleted_files")
                    os.makedirs(output_dir, exist_ok=True)
                    subprocess.run([ftk_tool_path, '--extract-deleted', os.path.join(IMAGES_DIR, selected_file.filename), output_dir], check=True)

        except subprocess.CalledProcessError:
            status = "Failed"

        # Log the FTK operation with the selected file ID
        new_ftk_op = FTKOps(
            operation=operation,
            status=status,
            user_id=current_user.id,
            file_id=selected_file_id if selected_file_id else None
        )
        db.session.add(new_ftk_op)
        db.session.commit()

        flash(f"Operation '{operation}' executed with status: {status}", "info")
        return redirect(url_for('ftk'))

    return render_template('ftk.html', form=form, logs=logs, uploaded_files=uploaded_files)


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
    
    if uploaded_file:
        if uploaded_file.status == 'Unscanned':
            # Delete the file from the filesystem
            file_path = os.path.join(MEM_DIR if uploaded_file.file_type == 'memory' else IMAGES_DIR, uploaded_file.filename)
            if os.path.exists(file_path):
                os.remove(file_path)
                
            # Delete the record from the database
            db.session.delete(uploaded_file)
            db.session.commit()
            flash('File deleted successfully!', 'success')
        elif uploaded_file.status == 'Scanned':
            # Update the status to 'file_deleted'
            uploaded_file.status = 'file_deleted'
            db.session.commit()
            flash('File marked as deleted!', 'success')

    else:
        flash('File not found!', 'danger')

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
    # Fetch the AutoScan record by report_id
    auto_scan = AutoScan.query.get(file_id)

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
        return jsonify({"error": "File not found"}), 404

    # Get the path of the file
    file_path = os.path.join(MEM_DIR if uploaded_file.file_type == 'memory' else IMAGES_DIR, uploaded_file.filename)
    output_dir = os.getenv('VOL_OUTPUT_DIR' if uploaded_file.file_type == 'memory' else 'TSK_OUTPUT_DIR')

    # Initialize metadata variable
    metadata = {}

    if uploaded_file.file_type == 'memory':
        metadata = fetch_memory_metadata(file_path, output_dir)
    elif uploaded_file.file_type == 'os_image':
        metadata = fetch_image_metadata(file_path, output_dir)  # Assuming similar function exists for image
    else:
        return jsonify({"error": "Unsupported file type"}), 400

    # Save metadata to a JSON file
    metadata_file_path = os.path.join(output_dir, f'{uploaded_file.filename}_metadata.json')
    with open(metadata_file_path, 'w') as json_file:
        json.dump(metadata, json_file)

    # Update the uploaded file record
    uploaded_file.has_metadata = True
    uploaded_file.metadata_file_path = metadata_file_path  # Store the JSON file path
    db.session.commit()  # Commit the changes to the database

    return jsonify({"message": "Metadata fetched successfully", "data": metadata, "metadata_file_path": metadata_file_path}), 200

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



if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
