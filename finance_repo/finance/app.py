import os

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd
import datetime
import re

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
    uid = session["user_id"]
    transaction_query = db.execute("select stock_symbol,sum(shares) as shares,price from transactions where user_id = :uid group by stock_symbol", uid = uid)
    cash_query = db.execute("select cash from users where id = :uid", uid = uid)
    cash = cash_query[0]["cash"]
    return render_template("index.html", results =  transaction_query, cash = cash)

@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""
    if request.method == "GET":
        return render_template("buy.html")
    else:
        symbol = request.form.get("symbol")
        shares = int(request.form.get("shares"))

        if not symbol:
            return apology("Please enter a stock symbol")

        if not shares:
            return apology("Please enter the number of shared you want to purchase")


        stock = lookup(symbol.upper())
        if not stock:
            return apology("The symbol you searched for doesn't exist")

        if shares < 0:
            return apology("Make sure number of stock is greater than 0!")

        total_price = shares * int(stock["price"])
        uid = session["user_id"]

        user = db.execute("select * from users where id = :id",id = uid)
        money_avail = user[0]["cash"]

        if money_avail < total_price:
            return apology("Not enough money in wallet to purchase desired stocks")

        new_money = money_avail - total_price
        db.execute("update users set cash = ? where id = ?",new_money,uid)

        curr_date = datetime.datetime.now()
        db.execute("insert into transactions(user_id,stock_symbol,shares,price,date) values (?,?,?,?,?)" ,uid, stock["symbol"],shares,stock["price"],curr_date)
        flash("You have succesfully bought the stock")
        return redirect("/")

@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    uid = session["user_id"]
    transaction_query = db.execute("select * from transactions where user_id = :uid", uid = uid)
    return render_template("history.html", transactions = transaction_query)

@app.route("/wallet", methods=["GET", "POST"])
@login_required
def wallet():
    """Show wallet"""
    uid = session["user_id"]
    if request.method == "GET":
        cash_query = db.execute("select cash from users where id = :uid", uid=uid)
        cash = cash_query[0]["cash"]
        return render_template("wallet.html", cash=cash)
    elif request.method == "POST":
        amount = int(request.form.get("amount"))

        if not amount:
            return apology("Please enter an amount to add to your wallet")

        cash_query = db.execute("select cash from users where id = :uid", uid=uid)
        cash = cash_query[0]["cash"]
        cash += amount
        db.execute("update users set cash = :cash where id = :uid", cash=cash, uid=uid)
        flash("You have successfully added money to your wallet!")
        return redirect("/")

@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password", 403)

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
    if request.method == "GET":
       return render_template("quote.html")

    elif request.method == "POST":
        symbol = request.form.get("symbol")
        if not symbol:
            return apology("Must provide stock symbol")

        stock = lookup(symbol.upper())

        if stock == None:
            return apology("Stock doesn't exist")
        else:
            return render_template("quoted.html", name = stock["name"], price = stock["price"], symbol = stock["symbol"])

@app.route("/changepassword", methods=["GET", "POST"])
@login_required
def changepass():
    uid = session["user_id"]
    if request.method == "GET":
        return render_template("changepassword.html")
    else:
        oldpassword = request.form.get("oldpass")
        newpassword = request.form.get("newpass")
        confirmpassword = request.form.get("newpassagain")
        user_query = db.execute("SELECT * FROM users WHERE id = :uid", uid=uid)
        hash = user_query[0]["hash"]

        if not oldpassword:
            return apology("Please enter your old password")
        if not newpassword:
            return apology("Please enter your new password")
        if not confirmpassword:
            return apology("Please re-enter your new password")

        if not check_password_hash(hash, oldpassword):
            return apology("Old password doesn't match")

        if newpassword != confirmpassword:
            return apology("Passwords don't match")

        newhash = generate_password_hash(newpassword)
        db.execute("UPDATE users SET hash=:newhash WHERE id=:uid", newhash=newhash, uid=uid)
        flash("Successfully changed password")
        return redirect("/")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    if request.method == "GET":
        return render_template("register.html")

    elif request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        confirmation = request.form.get("confirmation")

        if not username:
            return apology("Must enter username")

        if not password:
            return apology("Must enter password")

        if not confirmation:
            return apology("Must enter password")

        if password != confirmation:
            return apology("Please ensure the passwords match")

        if not re.search(r"^(?=.*[A-Za-z])(?=.*\d)(?=.*[@$!%*#?&])[A-Za-z\d@$!%*#?&]+$", password):
            return apology("Password must contain at least one letter, one number, and one special character.")

        hash = generate_password_hash(password)
        try:
            new_user = db.execute("insert into users(username,hash) values (?,?)",username, hash)
        except:
            return apology("User with same usrname already exists")

        session["user_id"] = new_user

        return redirect("/")

@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    uid = session["user_id"]

    if request.method == "GET":
        user_stocks = db.execute("SELECT stock_symbol FROM transactions WHERE user_id = :uid GROUP BY stock_symbol HAVING SUM(shares) > 0", uid=uid)
        return render_template("sell.html", symbols=user_stocks)

    else:
        symbol = request.form.get("symbol")
        shares = int(request.form.get("shares"))

        if not symbol:
            return apology("Please select a stock symbol")

        if not shares:
            return apology("Please enter the number of shared you want to sell")

        stock = lookup(symbol.upper())
        if not stock:
            return apology("The symbol you searched for doesn't exist")

        if shares < 0:
            return apology("Make sure number of stock is greater than 0!")

        user_shares = db.execute("select shares from transactions where user_id = :uid and stock_symbol = :symbol group by stock_symbol",uid = uid,symbol = symbol )
        usershares = user_shares[0]["shares"]

        if shares > usershares:
            return apology("You don't own enough of thh stock to sell")

        total_price = shares * int(stock["price"])
        uid = session["user_id"]

        user = db.execute("select * from users where id = :id",id = uid)
        money_avail = user[0]["cash"]

        new_money = money_avail + total_price
        db.execute("update users set cash = ? where id = ?",new_money,uid)

        curr_date = datetime.datetime.now()
        db.execute("insert into transactions(user_id,stock_symbol,shares,price,date) values (?,?,?,?,?)" ,uid, stock["symbol"],-1*(shares),stock["price"],curr_date)
        flash("You have succesfully sold the stock")
        return redirect("/")


