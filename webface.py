from flask import Flask, render_template, request, redirect, url_for, session, flash
import functools
from sqlitewrap import SQLite
from werkzeug.security import generate_password_hash, check_password_hash
from sqlite3 import IntegrityError
import random
import string
import datetime

#Podstránky
app = Flask(__name__)
app.secret_key = b"totoj e zceLa n@@@hodny retezec nejlep os.urandom(24)"
app.secret_key = b"x6\x87j@\xd3\x88\x0e8\xe8pM\x13\r\xafa\x8b\xdbp\x8a\x1f\xd41\xb8"



@app.route("/", methods=["GET"])
def home():
    return render_template("convertor.html")

#zkracovac - vytvoří krátkou adresu
def generate_short_url():
    characters = string.ascii_letters + string.digits
    short_url = "".join(random.choice(characters) for _ in range(5))
    return short_url


@app.route("/convertor/", methods=["GET"])
def convertor():

    """with SQLite("data.sqlite") as cursor:
            response = cursor.execute(
            "SELECT url_short FROM url ORDER BY datetime DESC"
            )
            
            url_short = list(response.fetchone())[0]
            shortened_url = request.url_root + url_short"""

    return render_template("convertor.html")

@app.route("/convertor/", methods=["POST"])
def convertor_post():

    url_short = generate_short_url()
    

    if "user" not in session:
        shortened_url = request.url_root + url_short

        return render_template("convertor.html", shortened_url = shortened_url)
       
    else:

        with SQLite("data.sqlite") as cursor:
            response = cursor.execute(
            "SELECT id FROM user WHERE login=?", [session["user"]]
            )
            
            user_id = list(response.fetchone())[0]

        user_login = session["user"]
        url = request.form.get("body")
        user_login = session["user"]
        shortened_url = request.url_root + url_short

        if url:
            with SQLite("data.sqlite") as cursor:
                cursor.execute(
                    "INSERT INTO url (user_id, user_login, url, url_short, datetime) VALUES (?,?,?,?,?)",
                    [user_id, user_login, url, url_short, datetime.datetime.now()]
                )

            return render_template("convertor.html", shortened_url = shortened_url)
            
    return redirect(url_for("convertor")) 
        
    


@app.route("/<url_short>")
def redirect_url(url_short):
    with SQLite("data.sqlite") as cursor:
        response = cursor.execute(
            "SELECT url FROM url WHERE url_short=?", [url_short]
        )
        original_url = response.fetchone()[0]
                
    return redirect(original_url)


#history
@app.route("/history/", methods=["GET"])
def history():
    if "user" not in session:
        flash("Pro přístup na tuto stránku se musíš přihlásit!")
        return redirect(url_for("login", url=request.path))
    
    with SQLite("data.sqlite") as cursor:
        response = cursor.execute(
            "SELECT user_login, url, url_short, datetime, id FROM url ORDER BY datetime DESC"
        )
        response = response.fetchall()

        


    return render_template("history.html", response = response, d=datetime.datetime)

#history - del
@app.route("/history/del/", methods=["POST"])
def history_del():
    id = request.form.get("id")
    if id:
        with SQLite("data.sqlite") as cursor:
            response = cursor.execute(
                "SELECT id FROM user WHERE login=?", [session["user"]]
            )
            user_id = response.fetchone()[0]
            cursor.execute(
                "DELETE FROM url WHERE id=? and user_id=?", [id, user_id] 
            )
    return redirect(url_for("history"))


#login
@app.route("/login/", methods=["GET"])
def login():
    return render_template("login.html")

@app.route("/login/", methods=["POST"])
def login_post():
    jmeno = request.form.get("jmeno", "")
    heslo = request.form.get("heslo", "")
    url = request.args.get("url", "")  # url je obsažená v adrese. proto request.args

    with SQLite('data.sqlite') as cursor:
        response = cursor.execute(f"SELECT login, passwd FROM user WHERE login = ?", [jmeno])
        response = response.fetchone()

        if response:
            login, passwd = response
            if check_password_hash(passwd, heslo):
                session["user"] = jmeno
                flash("Jsi přihlášen!", "success")
                if url:
                    return redirect(url)
                else:
                    return redirect(url_for("home"))
        
        flash("Nesprávné přihlašovací údaje!", "error")
        return redirect(url_for("login", url=url))

#Logout
@app.route("/logout/")
def logout():
    session.pop("user", None)
    flash("Byl jsi odhlášen!", "success")
    return redirect(url_for("home"))

#Register
@app.route("/register/", methods=["GET"])
def register():
    return render_template("register.html")

@app.route("/register/", methods=["POST"])
def register_post():
    jmeno = request.form.get('jmeno', '')
    heslo1 = request.form.get('heslo1', '')
    heslo2 = request.form.get('heslo2', '')

    if len(jmeno) <5:
        flash("Jmeno musí mít alespoň 5 znaků", "error")
        return redirect(url_for("register"))
    if len(heslo1) <5:
        flash("Heslo musí mít alespoň 5 znaků", "error")
        return redirect(url_for("register"))
    if heslo1 != heslo2:
        flash("Zadej dvakrát stejné heslo", "error")
        return redirect(url_for("register"))
        
    hash_ = generate_password_hash(heslo1)
    try:
        with SQLite("data.sqlite") as cursor:
            cursor.execute('INSERT INTO user (login,passwd) VALUES (?,?)', [jmeno, hash_])
        flash(f"Uživatel `{jmeno}` byl přidán!", "success")
    except IntegrityError:
         flash(f"Uživatel `{jmeno}` již existuje!", "error")

    return redirect(url_for("register"))