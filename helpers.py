from flask import redirect, session, flash
from functools import wraps

# Define login_required decorator
def login_required(f):
    """
    Decorate routes to require login.

    https://flask.palletsprojects.com/en/latest/patterns/viewdecorators/
    """

    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get("user_id") is None:
            return redirect("/login")
        return f(*args, **kwargs)

    return decorated_function

# Define admin_required decorator
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Check if user is logged in
        if session.get("user_id") is None:
            flash("You need to be logged in to access this page.")
            return redirect("/login")
        if session.get("user_id") != 1:
            flash("You do not have permission to access this page.")
            return redirect("/")

        return f(*args, **kwargs)

    return decorated_function
