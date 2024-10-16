# install the packages:
> pip install Flask Flask-SQLAlchemy Flask-Login
> pip install flask-wtf

> pip install Flask-Migrate
> pip install python-dotenv


# Update db Table:

flask db init
flask db migrate -m "Add has_metadata and metadata_file_path fields"
flask db upgrade
