import sqlite3
from flask import Flask, render_template, request, url_for, flash, redirect,session
from flask_login import UserMixin,login_user,LoginManager, current_user,login_required, logout_user
import time
import hashlib
import os
from cryptography.fernet import Fernet
import string
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret'
login_manager = LoginManager(app)
login_manager.login_view = "app"
limiter = Limiter(app, key_func=get_remote_address)


key = b'lemT0enYj9UyTBqCMPi8cZteOgiVbDq40mnKfRRoXrI='
fernet = Fernet(key)

allowed = string.ascii_lowercase + string.ascii_uppercase +'_'+'-'+'!'+string.digits+'.'+'/'+':'

def valid(string):
    if any(x not in allowed for x in string):
        return False
    else:
        return True

class User(UserMixin):
    def __init__(self, id, user_name, password):
         self.id = id
         self.user_name = user_name
         self.password = password
         self.authenticated = False

    def is_active(self):
        return self.is_active()

    def is_anonymous(self):
        return False

    def is_authenticated(self):
        return self.authenticated

    def is_active(self):
        return True

    def get_id(self):
        return self.id

@login_manager.user_loader
def load_user(user_id):
   conn = sqlite3.connect('database.db')
   curs = conn.cursor()
   curs.execute("SELECT * from users where id = (?)",[user_id])
   lu = curs.fetchone()
   if lu is None:
      return None
   else:
      return User(int(lu[0]), lu[1], lu[2])

def get_db_connection():
    conn = sqlite3.connect('database.db')
    conn.row_factory = sqlite3.Row
    return conn




@app.route('/')
def base():
    session['logged'] = False
    return render_template('base.html')



@app.route('/login')
def login():
    return render_template('login.html')

@app.route('/login', methods=['POST'])
@limiter.limit("10/hour",exempt_when=lambda: session['logged']==True)
def login_post():
    user_name = request.form['user_name']
    password = request.form['password']
    session['logged']=False

    time.sleep(2)

    if valid(user_name) and valid(password):
        con = get_db_connection()
        cur = con.cursor()
        cur.execute("select * from users where user_name=?", (user_name,))
        data = cur.fetchone()

        if not data:
            flash('Wrong user name or password')
            return redirect(url_for('login'))

        salt=data[3]
        key=data[2]

        if hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000) == key:
            session["user_name"] = data["user_name"]
            session["master"]=False
            login_user(load_user(data['id']))
            return redirect(url_for('profile'))
        else:
            flash('Wrong user name or password')
            return redirect(url_for('login'))
    else:
        flash('Unsupported characters')
        return redirect(url_for('login'))




@app.route('/signup')
def signup():
    return render_template('signup.html')

@app.route('/signup', methods=['POST'])
@limiter.limit("10/hour")
def signup_post():
    user_name = request.form['user_name']
    password = request.form['password']
    master = request.form['master']

    time.sleep(2)

    if valid(user_name) and valid(password) and valid(master):
        upper = string.ascii_uppercase
        lower = string.ascii_lowercase
        numbers = string.digits
        special = '_' + '-' + '!' + '.' + '/'
        is_8=len(password)>=8
        is_upper = any(x in upper for x in password)
        is_lower = any(x in lower for x in password)
        is_number = any(x in numbers for x in password)
        is_special = any(x in special for x in password)
        is_8m = len(password) >= 8
        is_upperm = any(x in upper for x in master)
        is_lowerm = any(x in lower for x in master)
        is_numberm = any(x in numbers for x in master)
        is_specialm = any(x in special for x in master)
        is_same=master is not password

        if is_upper and is_lower and is_number and is_special and is_8 and is_upperm and is_lowerm and is_numberm and is_specialm and is_8m and is_same:
            con = get_db_connection()
            cur = con.cursor()
            cur.execute("select * from users where user_name=?", (user_name,))
            data = cur.fetchone()

            if data:
                flash('User exists')
                return redirect(url_for('signup'))

            salt = os.urandom(32)
            key = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000)
            key_master = hashlib.pbkdf2_hmac('sha256', master.encode('utf-8'), salt, 100000)

            conn = get_db_connection()
            conn.execute('INSERT INTO users (user_name, password,salt,master) VALUES (?, ?,?,?)',
                        (user_name, key , salt , key_master))
            conn.commit()
            conn.close()

            return redirect(url_for('login'))
        else:
            flash("Weak password or master,should contain at least one upper and lower letter, number and special character and 8 characters. Master and password can't be the same")
            return redirect(url_for('signup'))
    else:
        flash('Unsupported characters')
        return redirect(url_for('signup'))




@app.route('/profile')
@login_required
def profile():
    id = current_user.id
    conn = get_db_connection()
    saved = conn.execute('SELECT * FROM saved where user_id=(?)',(id,)).fetchall()
    conn.close()
    return render_template('profile.html', saved=saved, name=current_user.user_name)

@app.route('/profile', methods=['POST'])
@login_required
def profile_post():
    master = request.form['master']
    if valid(master):
        id = current_user.id
        con = get_db_connection()
        cur = con.cursor()
        cur.execute("select * from users where id=(?)", (id,))
        data = cur.fetchone()
        salt = data[3]
        key = data[4]


        if hashlib.pbkdf2_hmac('sha256', master.encode('utf-8'), salt, 100000) == key:
            session['master']=True
            return redirect(url_for('profile_dec'))
        else:
            flash('Wrong master')
            return redirect(url_for('profile'))

    else:
        flash('Unsupported characters')
        return redirect(url_for('profile'))


@app.route('/profile/dec')
@login_required
def profile_dec():
    id=current_user.id
    conn = get_db_connection()
    saved = conn.execute('SELECT * FROM saved where user_id=(?)',[id]).fetchall()
    conn.close()
    leng=len(saved)
    dec = []
    for i in range(leng):
        dec.append(fernet.decrypt(saved[i][2]))

    return render_template('profile_dec.html', saved=saved, name=current_user.user_name,dec=dec,len=leng)




@app.route('/logout')
@login_required
def logout():
    session['master']=False
    session['logged'] = True
    logout_user()
    return redirect(url_for('login'))




@app.route('/profile/create/')
@login_required
def create():
    return render_template('create.html')

@app.route('/profile/create/', methods=['POST'])
@login_required
def create_post():
    id = current_user.id
    site = request.form['site']
    password = request.form['password']

    if valid(site) and valid(password):

        password_enc = fernet.encrypt(password.encode())

        conn = get_db_connection()
        conn.execute('INSERT INTO saved (site, password,user_id) VALUES (?, ?,?)',
                     [site,password_enc,id])
        conn.commit()
        conn.close()
        return redirect(url_for('profile'))
    else:
        flash("Unsupported characters")
        return redirect(url_for('create'))
        
if __name__ == '__main__':
    app.run()






