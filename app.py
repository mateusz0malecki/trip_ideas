from flask import Flask, render_template, request, url_for, flash, g, redirect, session
import sqlite3

import random
import string
import hashlib
import binascii

app_info = {
    'db_file': 'C:/Users/mmale/Desktop/Udemy_Flask/Projekt3_Trips_CRUD/data/base.db'
}
app = Flask(__name__)
app.config['SECRET_KEY'] = 'a_secret_key'


def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(app_info['db_file'])
    return db


class UserPass:

    def __init__(self, user='', password=''):
        self.user = user
        self.password = password
        self.email = ''
        self.is_valid = False
        self.is_admin = False

    def hash_password(self):
        """Hash a password for storing."""
        # the value generated using os.urandom(60)
        os_urandom_static = b"ID_\x12p:\x8d\xe7&\xcb\xf0=H1\xc1\x16\xac\xe5BX\xd7\xd6j\xe3i\x11\xbe\xaa\x05\xccc\xc2\
        xe8K\xcf\xf1\xac\x9bFy(\xfbn.`\xe9\xcd\xdd'\xdf`~vm\xae\xf2\x93WD\x04"
        salt = hashlib.sha256(os_urandom_static).hexdigest().encode('ascii')
        pwdhash = hashlib.pbkdf2_hmac('sha512', self.password.encode('utf-8'), salt, 100000)
        pwdhash = binascii.hexlify(pwdhash)
        return (salt + pwdhash).decode('ascii')

    def verify_password(self, stored_password, provided_password):
        """Verify a stored password against one provided by user"""
        salt = stored_password[:64]
        stored_password = stored_password[64:]
        pwdhash = hashlib.pbkdf2_hmac('sha512', provided_password.encode('utf-8'), salt.encode('ascii'), 100000)
        pwdhash = binascii.hexlify(pwdhash).decode('ascii')
        return pwdhash == stored_password

    def get_random_user_password(self):
        """Preparing random password for first admin-user"""
        random_user = ''.join(random.choice(string.ascii_lowercase) for i in range(3))
        self.user = random_user

        password_characters = string.ascii_letters  # + string.digits + string.punctuation
        random_password = ''.join(random.choice(password_characters) for i in range(3))
        self.password = random_password

    def login_user(self):
        """Logging user"""
        db = get_db()
        sql_statement = 'select id, name, email, password, is_active, is_admin from users where name=?'
        cur = db.execute(sql_statement, [self.user])
        user_record = cur.fetchone()

        if user_record is not None and self.verify_password(user_record[3], self.password):
            return user_record
        else:
            self.user = None
            self.password = None
            return None

    def get_user_info(self):
        """Getting stored info if user is active and is an admin"""
        db = get_db()
        sql_statement = 'select name, email, is_active, is_admin from users where name=?'
        cur = db.execute(sql_statement, [self.user])
        db_user = cur.fetchone()

        if db_user is None:
            self.is_valid = False
            self.is_admin = False
            self.email = ''
        elif db_user[2] != 1:
            self.is_valid = False
            self.is_admin = False
            self.email = db_user[1]
        else:
            self.is_valid = True
            self.is_admin = db_user[3]
            self.email = db_user[1]


@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()


@app.route('/', methods=['GET', 'POST'])
def index():
    cur_login = UserPass(session.get('user'))
    cur_login.get_user_info()

    if request.method == 'GET':
        db = get_db()
        sql_command = 'select id, name, email, description, completeness, contact from trips;'
        cur = db.execute(sql_command)
        trips = cur.fetchall()
        return render_template('index.html', trips=trips, active_menu='index', cur_login=cur_login)
    else:
        trip = request.form['name'] if 'name' in request.form else ''

        db = get_db()
        sql_command = 'select id, name, email, description, completeness, contact from trips where name=?;'
        cur = db.execute(sql_command, [trip])
        trip = cur.fetchone()

        return render_template('trip_added.html', trip=trip, active_menu='index', cur_login=cur_login)


@app.route('/new_trip', methods=['GET', 'POST'])
def new_trip():
    cur_login = UserPass(session.get('user'))
    cur_login.get_user_info()
    if not cur_login.is_valid:
        return redirect(url_for('login'))

    if request.method == 'GET':
        return render_template('new_trip.html', active_menu='new_trip', cur_login=cur_login)
    else:

        trip_name = '' if 'trip_name' not in request.form else request.form['trip_name']
        email = '' if 'email' not in request.form else request.form['email']
        description = '' if 'description' not in request.form else request.form['description']
        completeness = False if request.form['completeness'] == 'no' else True
        contact = False if 'contact' not in request.form else True

        db = get_db()
        sql_command = 'insert into trips(name, email, description, completeness, contact) values(?, ?, ?, ?, ?)'
        db.execute(sql_command, [trip_name, email, description, completeness, contact])
        db.commit()

        flash('Trip idea has been saved!')

        return redirect(url_for('index'))


@app.route('/all_trips')
def all_trips():
    cur_login = UserPass(session.get('user'))
    cur_login.get_user_info()
    if not cur_login.is_valid or not cur_login.is_admin:
        return redirect(url_for('login'))

    db = get_db()
    sql_command = 'select id, name, email, description, completeness, contact from trips;'
    cur = db.execute(sql_command)
    trips = cur.fetchall()
    return render_template('all_trips.html', trips=trips, active_menu='all_trips', cur_login=cur_login)


@app.route('/edit_trip/<trip_id>', methods=['GET', 'POST'])
def edit_trip(trip_id):
    cur_login = UserPass(session.get('user'))
    cur_login.get_user_info()
    if not cur_login.is_valid or not cur_login.is_admin:
        return redirect(url_for('login'))

    db = get_db()

    if request.method == 'GET':
        sql_command = 'select id, name, email, description, completeness, contact from trips where id=?;'
        cur = db.execute(sql_command, [trip_id])
        trip = cur.fetchone()
        if trip is None:
            flash('No such trip idea existing, sorry.')
            return redirect(url_for('all_trips'))
        else:
            return render_template('edit_trip.html', trip=trip, active_menu='all_trips', cur_login=cur_login)
    else:
        trip_name = '' if 'trip_name' not in request.form else request.form['trip_name']
        email = '' if 'email' not in request.form else request.form['email']
        description = '' if 'description' not in request.form else request.form['description']
        completeness = False if request.form['completeness'] == 'no' else True
        contact = False if 'contact' not in request.form else True

        sql_command = 'update trips set name=?, email=?, description=?, completeness=?, contact=? where id=?'
        db.execute(sql_command, [trip_name, email, description, completeness, contact, trip_id])
        db.commit()

        flash('Trip "{}" has been edited'.format(trip_name))
        return redirect(url_for('all_trips'))


@app.route('/delete_trip/<trip_id>')
def delete_trip(trip_id):
    cur_login = UserPass(session.get('user'))
    cur_login.get_user_info()
    if not cur_login.is_valid or not cur_login.is_admin:
        return redirect(url_for('login'))

    db = get_db()
    sql_statement = 'delete from trips where id = ?;'
    db.execute(sql_statement, [trip_id])
    db.commit()
    return redirect(url_for('all_trips'))


@app.route('/init_app')
def init_app():
    # check if there are users defined (at least one active admin required)
    db = get_db()
    sql_statement = 'select count(*) as cnt from users where is_active and is_admin;'
    cur = db.execute(sql_statement)
    active_admins = cur.fetchone()

    print(active_admins)

    if active_admins[0] > 0:
        flash('Application is already set-up. Nothing to do')
        return redirect(url_for('index'))
    else:
        # if not - create/update admin account with a new password and admin privileges, display random username
        user_pass = UserPass()
        user_pass.get_random_user_password()
        sql_statement = '''insert into users(name, email, password, is_active, is_admin)
                           values(?,?,?,True, True);'''
        db.execute(sql_statement, [user_pass.user, 'noone@blablabla', user_pass.hash_password()])
        db.commit()
        flash('User {} with password {} has been created'.format(user_pass.user, user_pass.password))
        return redirect(url_for('index'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    cur_login = UserPass(session.get('user'))
    cur_login.get_user_info()

    if request.method == 'GET':
        return render_template('login.html', cur_login=cur_login, active_menu='login')
    else:
        user_name = '' if 'user_name' not in request.form else request.form['user_name']
        user_pass = '' if 'user_pass' not in request.form else request.form['user_pass']

        new_login = UserPass(user_name, user_pass)
        login_record = new_login.login_user()

        if login_record is not None:
            session['user'] = user_name
            flash('Welcome {}'.format(user_name))
            return redirect(url_for('index'))
        else:
            flash('Wrong username or password, try again')
            return render_template('login.html', active_menu='login')


@app.route('/logout')
def logout():
    if 'user' in session:
        session.pop('user', None)
        flash('You have logged out')
    return redirect(url_for('index'))


@app.route('/users')
def users():
    cur_login = UserPass(session.get('user'))
    cur_login.get_user_info()
    if not cur_login.is_valid or not cur_login.is_admin:
        return redirect(url_for('login'))

    db = get_db()
    sql_command = 'select id, name, email, is_admin, is_active from users;'
    cur = db.execute(sql_command)
    all_users = cur.fetchall()
    return render_template('users.html', users=all_users, active_menu='users', cur_login=cur_login)


@app.route('/new_user', methods=['GET', 'POST'])
def new_user():
    cur_login = UserPass(session.get('user'))
    cur_login.get_user_info()
    if not cur_login.is_valid or not cur_login.is_admin:
        return redirect(url_for('login'))

    db = get_db()
    message = None
    user = {}

    if request.method == 'GET':
        return render_template('new_user.html', user=user, active_menu='users', cur_login=cur_login)
    else:
        user['user_name'] = '' if 'user_name' not in request.form else request.form['user_name']
        user['email'] = '' if 'email' not in request.form else request.form['email']
        user['user_pass'] = '' if 'user_pass' not in request.form else request.form['user_pass']

        cursor = db.execute('select count(*) as cnt from users where name = ?', [user['user_name']])
        record = cursor.fetchone()
        is_user_name_unique = (record[0] == 0)

        cursor = db.execute('select count(*) as cnt from users where email = ?', [user['email']])
        record = cursor.fetchone()
        is_user_email_unique = (record[0] == 0)

        if user['user_name'] == '':
            message = 'Name cannot be empty'
        elif user['email'] == '':
            message = 'email cannot be empty'
        elif user['user_pass'] == '':
            message = 'Password cannot be empty'
        elif not is_user_name_unique:
            message = 'User with the name {} already exists'.format(user['user_name'])
        elif not is_user_email_unique:
            message = 'User with the email {} already exists'.format(user['email'])

        if not message:
            user_pass = UserPass(user['user_name'], user['user_pass'])
            password_hash = user_pass.hash_password()
            sql_statement = '''insert into users(name, email, password, is_active, is_admin)
                          values(?,?,?, True, False);'''
            db.execute(sql_statement, [user['user_name'], user['email'], password_hash])
            db.commit()
            flash('User {} created'.format(user['user_name']))
            return redirect(url_for('users'))
        else:
            flash('Correct error: {}'.format(message))
            return render_template('new_user.html', user=user, active_menu='users', cur_login=cur_login)


@app.route('/edit_user/<user_name>', methods=['GET', 'POST'])
def edit_user(user_name):
    cur_login = UserPass(session.get('user'))
    cur_login.get_user_info()
    if not cur_login.is_valid or not cur_login.is_admin:
        return redirect(url_for('login'))

    db = get_db()
    cur = db.execute('select name, email from users where name = ?', [user_name])
    user = cur.fetchone()

    if user is None:
        flash('No such user')
        return redirect(url_for('users'))

    if request.method == 'GET':
        return render_template('edit_user.html', user=user, active_menu='users', cur_login=cur_login)
    else:
        new_email = '' if 'email' not in request.form else request.form['email']
        new_password = '' if 'user_pass' not in request.form else request.form['user_pass']

        if new_email != user[1]:
            sql_statement = "update users set email = ? where name = ?"
            db.execute(sql_statement, [new_email, user_name])
            db.commit()
            flash('Email was changed')

        if new_password != '':
            user_pass = UserPass(user_name, new_password)
            sql_statement = "update users set password = ?  where name = ?"
            db.execute(sql_statement, [user_pass.hash_password(), user_name])
            db.commit()
            flash('Password was changed')

        return redirect(url_for('users'))


@app.route('/delete_user/<user_name>')
def delete_user(user_name):
    cur_login = UserPass(session.get('user'))
    cur_login.get_user_info()
    if not cur_login.is_valid or not cur_login.is_admin:
        return redirect(url_for('login'))

    cur_login = session['user']

    db = get_db()
    sql_statement = "delete from users where name = ? and name <> ?"
    db.execute(sql_statement, [user_name, cur_login])
    db.commit()

    return redirect(url_for('users'))


@app.route('/user_status_change/<action>/<user_name>')
def user_status_change(action, user_name):
    cur_login = UserPass(session.get('user'))
    cur_login.get_user_info()
    if not cur_login.is_valid or not cur_login.is_admin:
        return redirect(url_for('login'))

    if 'user' not in session:
        return redirect(url_for('login'))
    cur_login = session['user']

    db = get_db()

    if action == 'active':
        db.execute("""update users set is_active = (is_active + 1) % 2 
                      where name = ? and name <> ?""",
                   [user_name, cur_login])
        db.commit()
    elif action == 'admin':
        db.execute("""update users set is_admin = (is_admin + 1) % 2 
                      where name = ? and name <> ?""",
                   [user_name, cur_login])
        db.commit()

    return redirect(url_for('users'))


if __name__ == '__main__':
    app.run()
