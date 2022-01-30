from flask import Flask, render_template, request, url_for, flash, redirect
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user, login_required, \
    fresh_login_required
from urllib.parse import urlparse, urljoin

import hashlib
import binascii

app = Flask(__name__)
app.config.from_pyfile('config.cfg')
db = SQLAlchemy(app)
login_manager = LoginManager(app)

login_manager.login_view = 'login'
login_manager.login_message = 'First, please log in using this form:'
login_manager.refresh_view = 'login'
login_manager.needs_refresh_message = 'You need to log in again:'


class Trips(db.Model):
    trip_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    name = db.Column(db.String(100), primary_key=False)
    email = db.Column(db.String(100), primary_key=False)
    description = db.Column(db.String(200), primary_key=False)
    completeness = db.Column(db.Boolean, primary_key=False)
    contact = db.Column(db.Boolean, primary_key=False)

    def __repr__(self):
        return '<id: {}, name: {}>'.format(self.trip_id, self.name)


class Users(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    name = db.Column(db.String(100), primary_key=False)
    email = db.Column(db.String(100), primary_key=False)
    password = db.Column(db.Text, primary_key=False)
    is_active = db.Column(db.Boolean, primary_key=False)
    is_admin = db.Column(db.Boolean, primary_key=False)

    def __repr__(self):
        return '<id: {}, name: {}>'.format(self.id, self.name)

    @staticmethod
    def hash_password(password):
        """Hash a password for storing."""
        # the value generated using os.urandom(60)
        os_urandom_static = b"ID_\x12p:\x8d\xe7&\xcb\xf0=H1\xc1\x16\xac\xe5BX\xd7\xd6j\xe3i\x11\xbe\xaa\x05\xccc\xc2\
        xe8K\xcf\xf1\xac\x9bFy(\xfbn.`\xe9\xcd\xdd'\xdf`~vm\xae\xf2\x93WD\x04"
        salt = hashlib.sha256(os_urandom_static).hexdigest().encode('ascii')
        pwdhash = hashlib.pbkdf2_hmac('sha512', password.encode('utf-8'), salt, 100000)
        pwdhash = binascii.hexlify(pwdhash)
        return (salt + pwdhash).decode('ascii')

    @staticmethod
    def verify_password(stored_password_hash, provided_password):
        """Verify a stored password against one provided by user"""
        salt = stored_password_hash[:64]
        stored_password = stored_password_hash[64:]
        pwdhash = hashlib.pbkdf2_hmac('sha512', provided_password.encode('utf-8'), salt.encode('ascii'), 100000)
        pwdhash = binascii.hexlify(pwdhash).decode('ascii')
        return pwdhash == stored_password


@login_manager.user_loader
def load_user(user_id):
    return Users.query.filter(Users.id == user_id).first()


def is_safe_url(target):
    ref_url = urlparse(request.host_url)
    test_url = urlparse(urljoin(request.host_url, target))
    return test_url.scheme in ('http', 'https') and ref_url.netloc == test_url.netloc


@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'GET':
        trips = Trips.query.all()
        return render_template('index.html', trips=trips, active_menu='index', cur_login=current_user)
    else:
        trip = request.form['name'] if 'name' in request.form else ''
        chosen_trip = Trips.query.filter(Trips.name == trip).first()

        return render_template('trip_added.html', trip=chosen_trip, active_menu='index', cur_login=current_user)


@app.route('/new_trip', methods=['GET', 'POST'])
@login_required
def new_trip():
    if request.method == 'GET':
        return render_template('new_trip.html', active_menu='new_trip', cur_login=current_user)
    else:

        trip_name = '' if 'trip_name' not in request.form else request.form['trip_name']
        email = '' if 'email' not in request.form else request.form['email']
        description = '' if 'description' not in request.form else request.form['description']
        completeness = False if request.form['completeness'] == 'no' else True
        contact = False if 'contact' not in request.form else True

        trip_to_add = Trips(name=trip_name, email=email, description=description, completeness=completeness,
                            contact=contact)
        db.session.add(trip_to_add)
        db.session.commit()

        flash('Trip idea has been saved!')
        return redirect(url_for('index'))


@app.route('/all_trips')
@login_required
@fresh_login_required
def all_trips():
    trips = Trips.query.all()
    return render_template('all_trips.html', trips=trips, active_menu='all_trips', cur_login=current_user)


@app.route('/edit_trip/<trip_id>', methods=['GET', 'POST'])
@login_required
@fresh_login_required
def edit_trip(trip_id):
    if request.method == 'GET':
        trip = Trips.query.filter(Trips.trip_id == trip_id).first()
        if trip is None:
            flash('No such trip idea existing, sorry.')
            return redirect(url_for('all_trips'))
        else:
            return render_template('edit_trip.html', trip=trip, active_menu='all_trips', cur_login=current_user)
    else:
        trip_name = '' if 'trip_name' not in request.form else request.form['trip_name']
        email = '' if 'email' not in request.form else request.form['email']
        description = '' if 'description' not in request.form else request.form['description']
        completeness = False if request.form['completeness'] == 'no' else True
        contact = False if 'contact' not in request.form else True

        trip = Trips.query.filter(Trips.trip_id == trip_id).first()
        trip.name = trip_name
        trip.email = email
        trip.description = description
        trip.completeness = completeness
        trip.contact = contact
        db.session.commit()

        flash('Trip "{}" has been edited'.format(trip_name))
        return redirect(url_for('all_trips'))


@app.route('/delete_trip/<trip_id>')
@login_required
@fresh_login_required
def delete_trip(trip_id):
    trip_to_delete = Trips.query.filter(Trips.trip_id == trip_id).first()
    db.session.delete(trip_to_delete)
    db.session.commit()
    flash('Trip "{}" has been deleted'.format(trip_to_delete.name))
    return redirect(url_for('all_trips'))


@app.route('/init_app')
def init_app():
    db.create_all()
    active_admins = Users.query.filter(Users.is_active, Users.is_admin).count()
    if active_admins > 0:
        flash('Application is already set-up. Nothing to do')
        return redirect(url_for('index'))
    else:
        new_admin = Users(id=1, name='admin', email='noone@blablabla', password=Users.hash_password('admin'),
                          is_active=True, is_admin=True)
        db.session.add(new_admin)
        db.session.commit()
        flash('User admin has been created')
        return redirect(url_for('index'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        return render_template('login.html', cur_login=current_user, active_menu='login')
    else:
        user_name = '' if 'user_name' not in request.form else request.form['user_name']
        user_pass = '' if 'user_pass' not in request.form else request.form['user_pass']
        remember = False if 'remember' not in request.form else request.form['remember']

        new_login = Users.query.filter(Users.name == user_name).first()
        if new_login is not None and Users.verify_password(new_login.password, user_pass):
            login_user(new_login, remember=remember)
            flash('Welcome {}'.format(user_name))

            next1 = request.args.get('next')
            if next1 and is_safe_url(next1):
                return redirect(next1)

            return redirect(url_for('index'))
        else:
            flash('Wrong username or password, try again')
            return render_template('login.html', cur_login=current_user, active_menu='login')


@app.route('/logout')
def logout():
    logout_user()
    flash('You have logged out')
    return redirect(url_for('index'))


@app.route('/users')
@login_required
@fresh_login_required
def users():
    all_users = Users.query.all()
    return render_template('users.html', users=all_users, active_menu='users', cur_login=current_user)


@app.route('/new_user', methods=['GET', 'POST'])
@login_required
@fresh_login_required
def new_user():
    message = None
    user = {}

    if request.method == 'GET':
        return render_template('new_user.html', user=user, active_menu='users', cur_login=current_user)
    else:
        user['user_name'] = '' if 'user_name' not in request.form else request.form['user_name']
        user['email'] = '' if 'email' not in request.form else request.form['email']
        user['user_pass'] = '' if 'user_pass' not in request.form else request.form['user_pass']

        cursor = Users.query.filter(Users.name == user['user_name']).count()
        is_user_name_unique = (cursor == 0)

        cursor = Users.query.filter(Users.name == user['email']).count()
        is_user_email_unique = (cursor == 0)

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
            user_to_add = Users(name=user['user_name'], email=user['email'],
                                password=Users.hash_password(user['user_pass']), is_active=True, is_admin=False)
            db.session.add(user_to_add)
            print(user_to_add)
            db.session.commit()
            flash('User {} created'.format(user['user_name']))
            return redirect(url_for('users'))
        else:
            flash('Correct error: {}'.format(message))
            return render_template('new_user.html', user=user, active_menu='users', cur_login=current_user)


@app.route('/edit_user/<user_name>', methods=['GET', 'POST'])
@login_required
@fresh_login_required
def edit_user(user_name):
    user = Users.query.filter(Users.name == user_name).first()

    if user is None:
        flash('No such user')
        return redirect(url_for('users'))

    if request.method == 'GET':
        return render_template('edit_user.html', user=user, active_menu='users', cur_login=current_user)
    else:
        new_email = '' if 'email' not in request.form else request.form['email']
        new_password = '' if 'user_pass' not in request.form else request.form['user_pass']

        if new_email != user.email:
            user.email = new_email
            db.session.commit()
            flash('Email was changed')

        if new_password != '':
            user.password = Users.hash_password(new_password)
            db.session.commit()
            flash('Password was changed')

        return redirect(url_for('users'))


@app.route('/delete_user/<user_name>')
@login_required
@fresh_login_required
def delete_user(user_name):
    user_to_delete = Users.query.filter(Users.name == user_name).filter(Users.id != current_user.get_id()).first()
    if user_to_delete is None:
        flash('You cannot delete yourself :)')
        return redirect(url_for('users'))
    db.session.delete(user_to_delete)
    db.session.commit()
    flash('User {} deleted.'.format(user_to_delete.name))
    return redirect(url_for('users'))


@app.route('/user_status_change/<action>/<user_name>')
@login_required
@fresh_login_required
def user_status_change(action, user_name):
    if action == 'active':
        user = Users.query.filter(Users.name == user_name).filter(Users.id != current_user.get_id()).first()
        if user:
            user.is_active = (user.is_active + 1) % 2
            db.session.commit()

    elif action == 'admin':
        user = Users.query.filter(Users.name == user_name).filter(Users.id != current_user.get_id()).first()
        if user:
            user.is_admin = (user.is_admin + 1) % 2
            db.session.commit()

    return redirect(url_for('users'))


if __name__ == '__main__':
    app.run()
