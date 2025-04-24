import platform
from cs50 import SQL
from flask import Flask, redirect, render_template, request, session
from flask_session import Session
from functools import wraps
from werkzeug.security import check_password_hash, generate_password_hash
from datetime import datetime

# Configure application
app = Flask(__name__)

# Auto-update templates when a change is made 
app.config["TEMPLATES_AUTO_RELOAD"] = True

# Configure session to use filesystem 
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///database.db")



# Function to use @login_required
def login_required(f):
    
    # Taken from https://flask.palletsprojects.com/en/1.1.x/patterns/viewdecorators/
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get("user_id") is None:
            return redirect("/login")
        return f(*args, **kwargs)
    return decorated_function
    

## REGISTRATION, LOG IN , LOG OUT ##
# Register user
@app.route("/register", methods=["GET", "POST"])
def register():

    # Clear user_id
    session.clear()

    if request.method == "POST":
        # Ensure a username was submitted
        if not request.form.get("username"):
            return render_template("register.html", error_no_username="*Please type in a username")
        
        # Query database for username
        dbusername = db.execute("SELECT username FROM users WHERE username = ?", request.form.get("username"))

        # Ensure username is not already taken
        if len(dbusername) == 1:
            return render_template("register.html", error_username_taken="*Username is already taken.")

        # Ensure password was submitted
        if not request.form.get("password"):
            return render_template("register.html", error_password="*Please type in your password")

        # Create user and Log user in after they successfully register
        if request.form.get("password"):
            db.execute("INSERT INTO users (username, hashed_password) VALUES (?, ?)", 
                        request.form.get("username"), 
                        generate_password_hash(request.form.get("password")))
            return login()

    # Show Register page.
    else:
        return render_template("register.html")
        

# Log user in 
@app.route("/login", methods=["GET", "POST"])
def login():

    # Clear user_id
    session.clear()

    # User submits form
    if request.method == "POST":
        # Ensure username was submitted
        if not request.form.get("username"):
            return render_template("login.html", error_no_username="*Please type in your username")

        # Ensure password was submitted
        if not request.form.get("password"):
            return render_template("login.html", error_password="*Please type in your password")

        # Query database for username
        results = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))

        # Ensure username exists and password is correct
        if len(results) != 1 or not check_password_hash(results[0]["hashed_password"], request.form.get("password")):
            return render_template("login.html", error_invalid="*Invalid password / username")

        # Remember which user has logged in
        session["user_id"] = results[0]["id"]

        # Redirect user to home page
        return redirect("/")

    # Display login page to user
    else:
        return render_template("login.html")


# Log user out 
@app.route("/logout", methods=["GET", "POST"])
def logout():
    # Clear user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")
## END REGISTRATION, LOG IN , LOG OUT ##


## MAIN PAGES ##
# Home page (Posting and viewing content)
@app.route("/", methods=["GET", "POST"])
@login_required
def home():
    fetch_query = """
            SELECT 
                posts.id,
                posts.title,
                posts.content,
                posts.time_stamp,
                users.username
            FROM posts
            JOIN users ON posts.user_id = users.id
            ORDER BY posts.time_stamp DESC;
            """
    
    # When user submits a post
    if request.method == "POST":
        title = request.form.get("title")
        content = request.form.get("content")

        # Ensure title is included
        if not title:
            error_title = "*Add a title"
            posts = db.execute(fetch_query)
            return render_template("home.html", error_title=error_title, posts=posts, content=content)

        # Ensure content of post is included
        if not content:
            error_content = "Write a comment."
            posts = db.execute(fetch_query)
            return render_template("home.html", error_content=error_content, posts=posts, title=title)

        # Get title and content user posts
        title = request.form.get("title")
        content = request.form.get("content")

        # Store title and content user posts in database
        db.execute("INSERT INTO posts (user_id, title, content) VALUES (?, ?, ?)", 
                    session["user_id"], title, content)
        
        posts = db.execute(fetch_query)
        return render_template("home.html", posts=posts)

    # Display homepage to user
    else:
        posts = db.execute(fetch_query)
        return render_template("home.html", posts=posts)


# My posts page (Viewing and deleting content)
@app.route("/my-posts", methods=["GET", "POST"])
@login_required
def my_posts():
    fetch_query = """
        SELECT
            posts.id,
            posts.title,
            posts.content,
            posts.time_stamp,
            users.username
        FROM posts
        JOIN users ON posts.user_id = users.id
        WHERE posts.user_id = ?
        ORDER BY posts.time_stamp DESC;
    """

    # When user wants to delete a post
    if request.method == "POST":
        post_id = request.form.get("post_id")
        # Delete user's post from database
        db.execute("DELETE FROM posts WHERE id = ? AND user_id = ? ", post_id, session["user_id"])
        # Load all posts from database after post was deleted
        user_posts = db.execute(fetch_query, session["user_id"])
        return render_template("my_posts.html", user_posts=user_posts)

    # Show page to user.
    user_posts = db.execute(fetch_query, session["user_id"])
    return render_template("my_posts.html",  user_posts=user_posts)
## END MAIN PAGES ##


## SETTINGS ##
# Load settings page
@app.route("/setting")
@login_required
def setting():
    # Get username and date of account creation of user from database
    user = db.execute("SELECT * FROM users WHERE id = ?", session["user_id"])
    username = user[0]["username"]
    created = user[0]["time_stamp"]

    # Calculate number of posts user posted
    post_length = len(db.execute("SELECT * FROM posts WHERE user_id = ?", session["user_id"]))
    return render_template("setting.html", username=username, created=created, post_length=post_length)


# Allow user to change password
@app.route("/password", methods=["GET", "POST"])
@login_required
def password():

    # User submits form to change password
    if request.method == "POST":

        # Get username and date of account creation of user from database
        user = db.execute("SELECT * FROM users WHERE id = ?", session["user_id"])
        username = user[0]["username"]
        created = user[0]["time_stamp"]

        # Calculate number of posts user posted
        post_length = len(db.execute("SELECT * FROM posts WHERE user_id = ?", session["user_id"]))

        # Ensure current password was submitted
        if not request.form.get("current_password"):
            error_password = "*Please type in your password"
            return render_template("setting.html", error_password=error_password, username=username, created=created, post_length=post_length)

        # Ensure current password is correct
        user = db.execute("SELECT * FROM users WHERE id = ?", session["user_id"])
        if not check_password_hash(user[0]["hashed_password"], request.form.get("current_password")):
            error_wrong_password = "*Incorrect password"
            return render_template("setting.html", error_wrong_password=error_wrong_password, username=username, created=created, post_length=post_length)

        # Ensure new password was submitted
        elif not request.form.get("new_password"):
            error_new_password = "*Please type in your new password"
            return render_template("setting.html", error_new_password=error_new_password, username=username, created=created, post_length=post_length)

        # Ensure password was reentered for confirmation
        elif not request.form.get("confirmation"):
            error_reenter_password = "*Please reenter your password"
            return render_template("setting.html", error_reenter_password=error_reenter_password, username=username, created=created, post_length=post_length)

        # Ensure new password was confirmed correctly
        elif request.form.get("new_password") != request.form.get("confirmation"):
            error_password_match = "*Passwords do not match"
            return render_template("setting.html", error_password_match=error_password_match, username=username, created=created, post_length=post_length)

        # Update password to new one
        elif request.form.get("new_password") == request.form.get("confirmation"):
            db.execute("UPDATE users SET hashed_password = ? WHERE id = ?", generate_password_hash(
                       request.form.get("new_password")), session["user_id"])
            success_password = "*Password successfully updated"
            return render_template("setting.html", success_password=success_password, username=username, created=created, post_length=post_length)

    # User reached route via GET
    else:
        return render_template("setting.html")


# Allow user to delete account
@app.route("/delete-account", methods=["GET", "POST"])
@login_required
def delete_account():

    # User submits form
    if request.method == "POST":

        # Get username and date of account creation of user from database
        user = db.execute("SELECT * FROM users WHERE id = ?", session["user_id"])
        username = user[0]["username"]
        created = user[0]["time_stamp"]

        # Calculate number of posts user posted
        post_length = len(db.execute("SELECT * FROM posts WHERE user_id = ?", session["user_id"]))

        # Ensure username was submitted
        if not request.form.get("delete-username"):
            error_username = "*Please type in your username"
            return render_template("setting.html", error_username=error_username, username=username, created=created, post_length=post_length)

        # Ensure password was submitted
        elif not request.form.get("delete-password"):
            error_password2 = "*Please type in your password"
            return render_template("setting.html", error_password2=error_password2, username=username, created=created, post_length=post_length)

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("delete-username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hashed_password"], request.form.get("delete-password")):
            error_invalid = "*Invalid password / username"
            return render_template("setting.html", error_invalid=error_invalid, username=username, created=created, post_length=post_length)

        username = request.form.get("delete-username")

        # Delete user's posts
        db.execute("DELETE FROM posts WHERE username = ? AND user_id = ?", username, session["user_id"])

        # Delete user from database
        db.execute("DELETE FROM users WHERE id = ?", session["user_id"])

        # Clear user_id
        session.clear()

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET
    else:
        return render_template("setting.html")
## END SETTINGS ##


### CUSTOM FUNCTION FOR NINJA FILTER
@app.template_filter("format_datetime")
# Formats DateTime from SQlite based on users operating system
def format_datetime(date_time):
    try:
        # Get python dateTime from string.
        parsed_date_time = datetime.strptime(date_time, "%Y-%m-%d %H:%M:%S")
        if platform.system() == "Windows":
            format = "%#I:%M %p, %B %d, %Y" # Hashtag instead of '-'
        else: 
            format = "%-I:%M %p, %B %d, %Y" # UNIX OS: '-' instead of Hashtag
        return parsed_date_time.strftime(format)
    except Exception:
        return date_time