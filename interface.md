# install the packages:
> pip install Flask Flask-SQLAlchemy Flask-Login
> pip install flask-wtf

> pip install Flask-Migrate
> pip install python-dotenv


# Update db Table:

flask db init
flask db migrate -m "Add has_metadata and metadata_file_path fields"
flask db upgrade


ram file samples:
 - https://corp.digitalcorpora.org/corpora/scenarios/2009-m57-patents/ram/

challenge.raw: https://drive.usercontent.google.com/download?id=1MjMGRiPzweCOdikO3DTaVfbdBK5kyynT&export=download&authuser=0


## report download as pdf
donwload and install wkhtmltopdf :  add install location to path in dash.env 
    default:"C:\Program Files\wkhtmltopdf\bin\wkhtmltopdf.exe"
> pip install pdfkit



: > flask db migrate -m "Add FTKActivityLog model"
: > flask db upgrade


# FTK IMAGER

for FTKAutomater:
    > pyautogui
    > pywinauto
    > easygui

ftkimager 
    --list-drives      >> List drives
    --verify [drive]   >> MD5 verification, Compute SHA1


Commands:

   [Detect / Show Drives](show detected physical drives )
        ftkimager --list-drives 

   [Create Image]
        ftkimager <source> <dest_file> --e01    
        
        e.g:  ftkimager \\.\PhysicalDrive0 "E:\MyDrive" --e01

    [Verification /Generate Hashes]
        ftkimager <source> <dest_file> --verify
    
    [GET / Print Image info / Preview ]
        ftkimager  <source> --print-info

    [Exporting Files]
        ftkimager <source_image> <destination_path>

    [ Recover Deleted Files]
        ftkimager <source> <dest_file>

    [Mounting Image]
        ftkimager <source> <dest_file> --verify
    
    [Live Ram Capture]
        ftkimager ram <dest_file>