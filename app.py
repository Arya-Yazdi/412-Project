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

# Configure Library to use SQLite database
db = SQL("sqlite:///database.db")
db.execute("PRAGMA foreign_keys = ON;")


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
        session["is_admin"] = results[0]["is_admin"]

        if session["is_admin"] == 1:
            return redirect("/admin")

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
    WITH ranked_posts AS (
        SELECT 
            posts.id,
            posts.title,
            posts.content,
            posts.time_stamp,
            users.username,
            users.is_admin,
            RANK() OVER (
                ORDER BY users.is_admin DESC, posts.time_stamp DESC
            ) AS rank_order
        FROM posts
        JOIN users ON posts.user_id = users.id
        )
        SELECT *
        FROM ranked_posts
        ORDER BY rank_order;
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


# Admin page (Viewing Audit Logs)
@app.route("/admin", methods=["GET"])
@login_required
def admin():
    if session.get("is_admin") == 0:
        return redirect("/")
    fetch_query = """
            SELECT 
                users.id,
                users.username,
                post_logs.post_id,
                post_logs.title,
                post_logs.operation,
                post_logs.time_stamp
            FROM post_logs
            JOIN users ON post_logs.user_id = users.id
            ORDER BY post_logs.time_stamp DESC;
            """

    logs = db.execute(fetch_query)
    return render_template("admin.html", logs=logs)
    

# My posts page (Viewing and deleting content)
@app.route("/my-posts", methods=["GET", "POST"])
@login_required
def my_posts():
    fetch_query = """
        WITH user_posts AS (
            SELECT
                posts.id,
                posts.title,
                posts.content,
                posts.time_stamp,
                users.username
            FROM posts
            JOIN users ON posts.user_id = users.id
            WHERE posts.user_id = ?
        )
        SELECT *
        FROM user_posts
        ORDER BY time_stamp DESC;
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
    user_info = getUserInfo()
    return render_template("setting.html", **user_info)


# Allow user to change password
@app.route("/password", methods=["GET", "POST"])
@login_required
def password():

    # User submits form to change password
    if request.method == "POST":
        user_info = getUserInfo()

        # Ensure current password was submitted
        if not request.form.get("current_password"):
            error_password = "*Please type in your password"
            return render_template("setting.html", 
                                   error_password=error_password, 
                                   **user_info)

        # Ensure current password is correct
        user = db.execute("SELECT hashed_password FROM users WHERE id = ?", session["user_id"])

        if not check_password_hash(user[0]["hashed_password"], request.form.get("current_password")):
            return render_template("setting.html", 
                                   error_wrong_password="*Incorrect password", 
                                   **user_info)

        # Ensure new password was submitted
        if not request.form.get("new_password"):
            return render_template("setting.html", 
                                   error_new_password="*Please type in your new password", 
                                   **user_info)

        # Ensure password was reentered for confirmation
        if not request.form.get("confirmation"):
            return render_template("setting.html", 
                                   error_reenter_password="*Please reenter your password", 
                                   **user_info)

        # Ensure new password was confirmed correctly
        if request.form.get("new_password") != request.form.get("confirmation"):
            return render_template("setting.html",
                                   error_password_match="*Passwords do not match", 
                                   **user_info)

        # Update user's password
        db.execute("UPDATE users SET hashed_password = ? WHERE id = ?", 
                   generate_password_hash(request.form.get("new_password")), session["user_id"])
        
        return render_template("setting.html", 
                                success_password="*Password successfully updated", 
                                **user_info)

    # User reached route via GET
    else:
        return redirect("/setting")


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
    
@app.template_filter("format_datetime_getdate")
# Formats DateTime from SQlite based on users operating system
def format_datetime(date_time):
    try:
        # Get python dateTime from string.
        parsed_date_time = datetime.strptime(date_time, "%Y-%m-%d %H:%M:%S")
        if platform.system() == "Windows":
            format = "%B %d, %Y" # Hashtag instead of '-'
        else: 
            format = "%B %d, %Y" # UNIX OS: '-' instead of Hashtag
        return parsed_date_time.strftime(format)
    except Exception:
        return date_time
    



### Basic Helper Functions
def getUserInfo():
    # Get username and date of account creation of user from database
    user = db.execute("SELECT username, joined_at FROM users WHERE id = ?", session["user_id"])
    username = user[0]["username"]
    joined = user[0]["joined_at"]

    # Calculate number of posts user posted
    rows = db.execute("SELECT COUNT(*) AS count FROM posts WHERE user_id = ?", session["user_id"])
    post_length = rows[0]["count"]

    return {
        "username": username,
        "joined": joined,
        "post_length": post_length
    }