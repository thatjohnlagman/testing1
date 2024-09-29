import os
import datetime

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import login_required, admin_required

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)


# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///barangay.db")

# Turn off cache to ensure new version of HTML is downloaded@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response

@app.route("/", methods=["GET", "POST"])
@login_required
def index():
    # List of documents
    documents = ["Certificate of Indigency", "Barangay Clearance", "Barangay Certificate", "Barangay ID", "Certificate of First Time Job Seeker", "Barangay Certification of Land Ownership"]

    # If the user clicked the submit buton do the following codes below
    if request.method == "POST":
        user_id = session["user_id"]
        name = request.form.get("name")
        age = request.form.get("age")
        sex = request.form.get("sex")
        address = request.form.get("address")
        purpose = request.form.get("purpose")
        file = request.form.get("file")
        validId = request.files.get("validId")

        # Flash error information if the info required is not provided
        if not name:
            flash("No name provided.")
            return render_template("index.html")
        if not age:
            flash("No age provided.")
            return render_template("index.html")
        if not sex:
            flash("No sex provided.")
            return render_template("index.html")
        if not address:
            flash("No address provided.")
            return render_template("index.html")
        if not purpose:
            flash("No purpose provided.")
            return render_template("index.html")
        if not file:
            flash("No file provided.")
            return render_template("index.html")
        if not validId:
            flash("No valid ID provided.")
            return render_template("index.html")

        # Save the file the user uploaded
        validId.save(os.path.join('static', 'uploads', validId.filename))
        path = os.path.join('static', 'uploads', validId.filename)

        # If the selected file is not in the list flash error
        if file not in documents:
            flash("Invalid purpose.")
            return render_template("index.html")

        # Insert new data into the database (request table)
        try:
            db.execute(
                "INSERT INTO request (user_id, name, age, sex, address, purpose, file, validId, dateRequested) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                session["user_id"], name, age, sex, address, purpose, file, path, datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        except:
            flash("An Error Occured.")
            return render_template("index.html")

        flash("Document Requested!")

        return redirect("/")

    # If the user views the index.html page execute the codes below
    else:
        # Finds the profile picture of the user
        profile_path = db.execute("SELECT image FROM users WHERE id = ?", session["user_id"])
        if len(profile_path) == 0:
            flash("User not found.")
            return render_template("index.html")
        profile_image = profile_path[0]['image']
        profile_name = db.execute("SELECT name FROM users WHERE id = ?", session["user_id"])[0]['name']

        return render_template("index.html", documents=documents, path=profile_image, name=profile_name)



@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Clear all the data stored in the previous session
    session.clear()

    if request.method == "POST":

        # Flash error information if the info required is not provided
        if not request.form.get("email"):
            flash("No email provided.")
            return render_template("login.html")

        elif not request.form.get("password"):
            flash("No password provided.")
            return render_template("login.html")

        # Query the database for the inputted email address
        rows = db.execute("SELECT * FROM users WHERE email = ?", request.form.get("email"))

        # If the email is not on the database or the password inputted is incorrect
        if len(rows) != 1 or not check_password_hash(rows[0]["password"], request.form.get("password")):
            flash("Wrong email or password.")
            return render_template("login.html")

        # Create a session for the signed in user
        session["user_id"] = rows[0]["id"]

        return redirect("/")

    else:
        return render_template("login.html")

@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    if request.method == "POST":
        # Get data from input field in the HTML
        name = request.form.get("name")
        email = request.form.get("email")
        password = request.form.get("password")
        confirmation = request.form.get("confirmPassword")
        sex = request.form.get("sex")
        dob = request.form.get("dob")
        profilePic = request.files.get("profilePic")

        # Flash error information if the info required is not provided
        if not name:
            flash("No name provided.")
            return render_template("register.html")
        if not email:
            flash("No Email provided.")
            return render_template("register.html")
        if not password:
            flash("No password provided.")
            return render_template("register.html")
        if not confirmation:
            flash("Please input a confirmation password.")
            return render_template("register.html")
        if password != confirmation:
            flash("Password do not match")
            return render_template("register.html")
        if not dob:
            flash("No date of birth provided")
            return render_template("register.html")
        if not sex:
            flash("No gender provided")
            return render_template("register.html")

        # Generate a hashed password
        hash = generate_password_hash(password)

        # If the user does not provide a profile picture, use the default instead
        if not profilePic:
            path = os.path.join('profilepic', "default-profile.jpg")
        # Else, save the uploaded picture and get the path to store to the database later
        else:
            profilePic.save(os.path.join('profilepic', profilePic.filename))
            path = os.path.join('profilepic', profilePic.filename)

        # Inserts user login information in the database (users table)
        try:
            new_user = db.execute(
                "INSERT INTO users (email, password, name, date_of_birth, sex, image) VALUES (?, ?, ?, ?, ?, ?)", email, hash, name, dob, sex, path)
        except:
            flash("Username already exists.")
            return render_template("register.html")

        # Assigns current session to user ID
        session["user_id"] = new_user

        return redirect("/")

    else:
        return render_template("register.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Clear all the data stored in the previous session
    session.clear()

    return redirect("/")

@app.route("/history")
@login_required
def history():
    # Finds the profile picture of the user
    profile_path = db.execute("SELECT image FROM users WHERE id = ?", session["user_id"])
    if len(profile_path) == 0:
            flash("No gender provided")
            return render_template("index.html")
    profile_image = profile_path[0]['image']

    profile_name = db.execute("SELECT name FROM users WHERE id = ?", session["user_id"])[0]['name']

    # Pulls status, date, verdict, file, and date requested data from the database (request table) ordered descendingly by dateRequested
    requests = db.execute("SELECT status, date, verdict, file, dateRequested, SUBSTR(dateRequested, 1, 19) as sortableDate FROM request WHERE user_id = ? ORDER BY sortableDate DESC", session["user_id"])


    return render_template("history.html", path=profile_image, name=profile_name, requests=requests)


# Admin side code

@app.route("/server_login", methods=["GET", "POST"])
def server_login():
    """Admin Log In"""

    # Clear all the data stored in the previous session
    session.clear()

    if request.method == "POST":

        email = request.form.get("email")
        password = request.form.get("password")

        # Flash error information if the info required is not provided
        if not email:
            flash("No email provided.")
            return render_template("server_login.html")

        elif not password:
            flash("No password provided.")
            return render_template("server_login.html")

        if email != "supersecretemail@gmail.com" or password != "supersecretpassword":
            flash("Wrong email or password.")
            return render_template("server_login.html")

        admin_user_id = 1

        session["user_id"] = admin_user_id

        return redirect("/server_approval")

    else:
        return render_template("server_login.html")


@app.route("/server_approval", methods=["GET", "POST"])
@admin_required
def server_approval():
    if request.method == "POST":
        action = request.form.get('action')
        request_id = request.form.get('request_id')
        date_estimate = request.form.get('date')

        # Modifies the data inside the database based on admin decision
        if action == 'accept':
            flash('Request accepted!')
            db.execute("UPDATE request SET verdict = 'pending' WHERE id = ?", (request_id,))
            db.execute("UPDATE request SET date = ? WHERE id = ?", date_estimate, request_id)

        elif action == 'deny':
            flash('Request Denied!')
            db.execute("UPDATE request SET verdict = 'denied' WHERE id = ?", (request_id,))

        if action == 'completed':
            flash('Request Completed!')
            db.execute("UPDATE request SET verdict = 'completed' WHERE id = ?", (request_id,))

        elif action == 'cancel':
            flash('Request Cancelled!')
            db.execute("UPDATE request SET verdict = 'cancelled' WHERE id = ?", (request_id,))

        return redirect("/server_approval")

    else:
        # Fetch all requests
        requests = db.execute("SELECT id, name, age, sex, address, file, purpose, dateRequested, date, validID, verdict FROM request")

        return render_template("server_approval.html", name="Admin", requests=requests)


@app.route("/server_history")
@login_required
@admin_required
def server_history():
    # Fetch requests with verdict 'completed' or 'denied' for all users
    requests = db.execute("SELECT name, address, status, date, verdict, file, dateRequested, SUBSTR(dateRequested, 1, 19) as sortableDate FROM request WHERE verdict IN ('completed', 'denied', 'cancelled') ORDER BY sortableDate DESC")

    return render_template("server_history.html", name="Admin", requests=requests)
