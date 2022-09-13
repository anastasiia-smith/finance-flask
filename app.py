import os

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")

# Make sure API key is set
if not os.environ.get("API_KEY"):
    raise RuntimeError("API_KEY not set")


@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""

    # Select amount of cash of current user
    cash_db = db.execute("SELECT cash FROM users WHERE id = ?", session["user_id"])
    cash = cash_db[0]["cash"]

    # Select transactions with type buy for current user

    transactions = db.execute("SELECT name, shares, symbol FROM portfolio WHERE user_id = ? ORDER BY id",
                              session["user_id"])

    # Separate shares, names, symbols in sublists

    names_list = []
    shares_list = []
    symbols_list = []

    for i in range(len(transactions)):
        names_list.append(transactions[i]["name"])
        shares_list.append(transactions[i]["shares"])
        symbols_list.append(transactions[i]["symbol"])

    # Get the current price of current user's stocks
    price = []
    for i in range(len(symbols_list)):
        stocks = lookup(symbols_list[i])
        price.append(stocks["price"])

    # Count total amount of current user's money
    sum = 0
    for i in range(len(price)):
        sum += price[i] * shares_list[i]

    grand_total = sum + cash

    return render_template("index.html", transactions=transactions, cash=cash, price=price,
                           grand_total=grand_total, names_list=names_list, shares_list=shares_list, symbols_list=symbols_list)


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""

    if request.method == "POST":
        # Get symbol from form
        symbol = request.form.get("symbol")

        # Find stock information in api
        stock = lookup(symbol)
        if not stock:
            return apology("stock doesn't exist", 400)

        # Get number of shares from form and check if positive int
        try:
            shares = int(request.form.get("shares"))
            if shares <= 0:
                return apology("Number of shares must be more than 0", 400)
        except:
            return apology("Not a whole number of shares", 400)

        # Select amount of cash of current user
        cash_db = db.execute("SELECT cash FROM users WHERE id = ?", session["user_id"])
        cash = cash_db[0]["cash"]

        # Find the price of the current stock multiplied by shares
        price = stock["price"] * shares

        # Find if enough money
        diff = cash - price
        if diff < 0:
            return apology("Not enough cash for current transaction", 400)

        # Update money from cash when buying
        db.execute("UPDATE users SET cash = ? WHERE id = ?", diff, session["user_id"])

        # Add transaction to database history()
        db.execute("INSERT INTO transactions (user_id, symbol, shares, type, name, price) VALUES(?, ?, ?, ?, ?, ?)",
                   session["user_id"], symbol, shares, "buy", stock["name"], stock["price"])

        # if stosk not in portfolio
        portfolio_db = db.execute("SELECT * FROM portfolio WHERE user_id = ? AND name = ?",
                                  session["user_id"], stock["name"])

        if not portfolio_db:
            db.execute("INSERT INTO portfolio (user_id, symbol, shares, name) VALUES(?, ?, ?, ?)",
                       session["user_id"], symbol, shares, stock["name"])
        else:
            shares_upd = portfolio_db[0]["shares"] + shares
            db.execute("UPDATE portfolio SET shares = ? WHERE user_id = ? AND id = ?",
                       shares_upd, session["user_id"], portfolio_db[0]["id"])

        return redirect("/")
    else:
        return render_template("buy.html")


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""

    stocks_db = db.execute("SELECT symbol, name, shares, time, type, price FROM transactions WHERE user_id = ?",
                           session["user_id"])

    return render_template("history.html", stocks=stocks_db)


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 400)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 400)

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password", 400)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    """Get stock quote."""
    if request.method == "POST":
        stock = lookup(request.form.get("symbol"))

        if not stock:
            return apology("stock doesn't exist", 400)

        return render_template("quoted.html", name=stock["name"], price=stock["price"])

    else:
        return render_template("quote.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""

    if request.method == "POST":
        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 400)

        # Ensure password was submitted
        elif (not request.form.get("password")) or (not request.form.get("confirmation")):
            return apology("must provide password", 400)

        # and passwords fields are the same
        elif request.form.get("password") != request.form.get("confirmation"):
            return apology("passwords dont match", 400)

        username = request.form.get("username")
        hash = generate_password_hash(request.form.get("password"))

        if db.execute("SELECT username FROM users WHERE username = ?", username):
            return apology("user with this name already exists", 400)

        # Add username and hash to database
        db.execute("INSERT INTO users (username, hash) VALUES(?, ?)", username, hash)

        # Log in user
        session["user_id"] = (db.execute("SELECT id FROM users WHERE username = ?", username))[0]["id"]

        # Redirect user to home page
        return redirect("/")

    else:
        return render_template("register.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""

    if request.method == "POST":
        # Get symbol and shares and check if user selected it
        symbol = request.form.get("symbol")

        try:
            shares = int(request.form.get("shares"))
            if shares <= 0:
                return apology("Number of shares must be more than 0", 400)
        except:
            return apology("Not a whole number of shares", 400)

        if not symbol or not shares:
            return apology("select valid stock ot amount of shares", 400)

        # Find stock information
        stock = lookup(symbol)
        if not stock:
            return apology("stock doesn't exist", 400)

        # Get shares from db and check if user didn't select more than has
        shares_db = db.execute("SELECT shares FROM portfolio WHERE user_id = ? AND symbol = ?",
                               session["user_id"], symbol)

        if shares_db[0]["shares"] < shares:
            return apology("you selected more shares than you have", 400)

        # Update shares in portfolio db if 0 delete from table
        shares_upd = shares_db[0]["shares"] - shares

        if shares_upd == 0:
            db.execute("DELETE FROM portfolio WHERE user_id = ? AND symbol = ?",
                       session["user_id"], symbol)
        else:
            db.execute("UPDATE portfolio SET shares = ? WHERE user_id = ? AND symbol = ?",
                       shares_upd, session["user_id"], symbol)

        # Select amount of cash of current user
        cash_db = db.execute("SELECT cash FROM users WHERE id = ?", session["user_id"])
        cash = cash_db[0]["cash"]

        # Update cash balance

        # Find the price of the current stock multiplied by shares
        price = stock["price"] * shares

        cash_upd = cash + price

        # Update cash
        db.execute("UPDATE users SET cash = ? WHERE id = ?", cash_upd, session["user_id"])

        # Add transaction to database history()
        db.execute("INSERT INTO transactions (user_id, symbol, shares, type, name, price) VALUES(?, ?, ?, ?, ?, ?)",
                   session["user_id"], symbol, shares, "sell", stock["name"], stock["price"])

        return redirect("/")

    else:
        symbols = db.execute("SELECT symbol FROM portfolio WHERE user_id = ?", session["user_id"])
        return render_template("sell.html", symbols=symbols)


@app.route("/change_password", methods=["GET", "POST"])
@login_required
def change_password():
    """Change password"""
    if request.method == "POST":
        old_password = request.form.get("old_password")
        new_password = request.form.get("new_password")
        confirmation = request.form.get("confirmation")

        if not old_password:
            return apology("Old password can't be empty ", 400)
        elif not new_password:
            return apology("New password can't be empty ", 400)
        elif not confirmation:
            return apology("Confirmationcan't be empty ", 400)

        # Get old password hash
        old_hash = db.execute("SELECT hash FROM users WHERE id = ?", session["user_id"])
        # and compare to old password input
        if not check_password_hash(old_hash[0]["hash"], old_password):
            return apology("Old password is not correct", 400)

        # Check if new password is matcing the confirmation
        elif new_password != confirmation:
            return apology("New password is not matcing the confirmation", 400)

        # Hash the new password and update in the db
        hash = generate_password_hash(new_password)
        db.execute("UPDATE users SET hash = ? WHERE id = ?", hash, session["user_id"])

        return redirect("/")

    else:
        return render_template("change_password.html")

