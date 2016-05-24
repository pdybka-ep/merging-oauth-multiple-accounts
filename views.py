import json
from urllib3 import response
import bcrypt
import sys
from flask import render_template, request, url_for, flash, session
from flask_login import LoginManager, login_required, login_user, current_user, logout_user
from werkzeug.utils import redirect
from app import app, db
# import sys
# sys.path.insert(0, '/external_auth')
#
# from external_auth.oauth_login.py import OAuthLogin
from models import *
from oauth_login import OAuthLogin
from task import taskman

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'success'


# callback to reload the user object
@login_manager.user_loader
def load_user(id):
    return UserAccount.query.get(int(id))


@app.route('/success')
def success():
    # if user is logging in via oauth
    if 'async_operation_id' in session:
        async_operation_id = session['async_operation_id']
        async_operation = AsyncOperation.query.filter_by(id=async_operation_id).join(UserExternalLogin).first()
        user_external_login = UserExternalLogin.query.filter_by(id=async_operation.user_external_login_id).first()
        user = UserAccount.query.filter_by(id=user_external_login.user_account_id).first()
        login_user(user, True)
        session['logged_in'] = True

    # the list of external providers that current user used to log in
    connected_providers = db.session.query(ExternalAuthenticationProvider.name).join(UserExternalLogin).join(
            UserAccount).filter_by(id=current_user.id).all()

    # selected providers used by user to log in
    subquery = db.session.query(ExternalAuthenticationProvider.name).join(UserExternalLogin).join(
            UserAccount).filter_by(id=current_user.id).subquery()

    # select external providers that are available to connect to current user account
    unconnected_providers = db.session.query(ExternalAuthenticationProvider.name).filter(
            ~ExternalAuthenticationProvider.name.in_(subquery)).all()
    todos = TodoItem.query.filter_by(user_account_id=current_user.id).all()

    return render_template('my-logins.html', connected_providers=connected_providers,
                           unconnected_providers=unconnected_providers, todos=todos)


@login_required
@app.route('/new-todo', methods=['GET', 'POST'])
def new_todo():
    if request.method == 'POST':
        todo = TodoItem(name=request.form['name'],
                        deadline_date=datetime.datetime.strptime(request.form['deadline_date'], "%m/%d/%Y").date(),
                        user_account_id=current_user.id)
        db.session.add(todo)
        db.session.commit()
        return redirect(url_for('success'))
    else:
        return render_template(
                'new-todo.html',
                page='new-todo'
        )


@app.route('/')
def index():
    return redirect(url_for('login_form'))


@login_required
@app.route('/mark-done/<int:todo_id>', methods=['POST'])
def mark_done(todo_id):
    if request.method == 'POST':
        todo = TodoItem.query.get(todo_id)
        todo.is_done = True
        db.session.commit()
        return redirect('/success')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))


@app.route('/error')
def error():
    return render_template('error.html')


@app.route('/preloader')
def preloader():
    return render_template('preloader.html')


@app.route('/login', methods=['GET', 'POST'])
def login_form():
    if request.method == 'POST':
        user_details = UserDetails.query.filter_by(email=request.form['email']).first()
        if not user_details:
            print "there is not user with such an email"
        password = request.form['password'].encode('utf-8')
        if bcrypt.hashpw(password, user_details.password_hash.encode('utf-8')) == user_details.password_hash.encode(
                'utf-8'):
            user = UserAccount.query.filter_by(user_details_id=user_details.id).first()
            login_user(user)
            session['logged_in'] = True
            return redirect(url_for('success'))
        else:
            print "Wrong password"
    else:
        return render_template('login-form.html')


@app.route('/add-login')
def add_login_page():
    return render_template('add-login.html')


@app.route('/signup', methods=['GET', 'POST'])
def create_new_account():
    if request.method == 'POST':
        first_name = request.form['first_name']
        last_name = request.form['last_name']
        email = request.form['email']
        password = request.form['password'].encode('utf-8')
        retype_password = request.form['retype_password'].encode('utf-8')
        # if the same email was used to log in
        if email == UserExternalLogin.query.filter_by(email=email).first():
            provider = UserExternalLogin.query.filter_by(email=email).join(ExternalAuthenticationProvider).first()
            flash('This email was already used to login with' + str(provider.name))
        if password == retype_password:
            password_salt = bcrypt.gensalt()  # generate salt
            password_hash = bcrypt.hashpw(password, password_salt)  # generate password hash

            user_details = UserDetails(first_name=first_name, last_name=last_name, email=email,
                                       password_hash=password_hash,
                                       password_salt=password_salt)
            db.session.add(user_details)
            db.session.commit()

            new_user = UserAccount(screen_user_name=first_name + ' ' + last_name, user_details_id=user_details.id)
            db.session.add(new_user)
            db.session.commit()
            login_user(new_user)
            return redirect(url_for('success'))
        else:
            flash('Passwords don\'t match')
            return redirect(url_for('/signup'))
    else:
        return render_template('signup-form.html')


@app.route('/authorize/<provider>')
def oauth_authorize(provider):
    oauthLogin = OAuthLogin.get_provider(provider)
    return oauthLogin.begin_auth()


# returns status of the async operation
@app.route('/get-status')
def get_status():
    if 'async_operation_id' in session:
        async_operation_id = session['async_operation_id']
        # retrieve from database the status of the stored in session async operation
        async_operation = AsyncOperation.query.filter_by(id=async_operation_id).join(AsyncOperationStatusType).first()
        status = str(async_operation.async_operation_status_type.name)
    else:
        print "async operation not in session"
        return redirect(url_for('error'))

    return status


@app.route('/callback/<provider>')
def show_preloader_start_authentication(provider):
    # store the id of the asynchronous operation in the session
    status_pending = AsyncOperationStatusType.query.filter_by(name='pending').first()
    external_authentication_provider = ExternalAuthenticationProvider.query.filter_by(name=provider).first()
    async_operation = AsyncOperation(async_operation_status_type_id=status_pending.id,
                                     external_authentication_provider_id=external_authentication_provider.id)
    db.session.add(async_operation)
    db.session.commit()
    # store in a session the id of the asynchronous operation
    session['async_operation_id'] = str(async_operation.id)
    taskman.add_task(external_auth, provider)

    return redirect(url_for('preloader'))


def external_auth(provider):
    oauth = OAuthLogin.get_provider(provider)
    external_id, email, first_name, last_name, name, login = oauth.get_user_data()
    if external_id is None:
        flash('Authentication failed')
        # change the status of async operation for 'error'
        status_error = AsyncOperationStatusType.query.filter_by(name='error').first()
        async_operation = AsyncOperation.query.filter_by(id=session['async_operation_id']).first()
        async_operation.async_operation_status_id = status_error.id
        db.session.add(async_operation)
        db.session.commit()
        return redirect(url_for('error'))
    # retrieve the user data from the database
    user_login = UserExternalLogin.query.filter_by(external_user_id=external_id).first()

    # if the user is new, we store theirs credentials in user_profile table
    if not user_login:
        # user logs in via oauth for the first time
        if not session.get('logged_in'):
            screen_user_name = name
            user_account = UserAccount(screen_user_name=screen_user_name)
            db.session.add(user_account)
            db.session.commit()
        # logged user wants to add social account
        else:
            user_account = UserAccount.query.filter_by(id=current_user.id).first()

        # create record in user_external_login table
        external_authentication_provider = ExternalAuthenticationProvider.query.filter_by(name=provider).first()
        user_login = UserExternalLogin(external_user_id=external_id, email=email, first_name=first_name,
                                       last_name=last_name, name=name,
                                       login_name=login,
                                       user_account_id=user_account.id,
                                       external_authentication_provider_id=external_authentication_provider.id)

        db.session.add(user_login)
        db.session.commit()
    # if the user login exists in the database
    else:
        # connect to the existing user account
        if session.get('logged_in'):
            todo_items = db.session.query(TodoItem).join(UserAccount).join(UserExternalLogin).filter_by(
                    external_user_id=external_id).all()
            for todo_item in todo_items:
                todo_item.user_account_id = current_user.id
                db.session.add(todo_item)

            # existing user login
            user_login = UserExternalLogin.query.filter_by(external_user_id=external_id).first()

            # other user logins that are be connected to the same account like the login that user wants to connect
            user_logins = UserExternalLogin.query.filter_by(user_account_id=user_login.user_account_id).all()
            for login in user_logins:
                login.user_account_id = current_user.id
                db.session.add(user_login)
            db.session.commit()

    # change the status of the async operation for 'ok' and insert the value of the user id
    # to the async_operation table
    status_ok = AsyncOperationStatusType.query.filter_by(name='ok').first()
    async_operation = AsyncOperation.query.filter_by(id=session['async_operation_id']).first()
    async_operation.async_operation_status_type_id = status_ok.id
    # connect the async_operation with user_profile
    async_operation.user_external_login_id = UserExternalLogin.query.filter_by(id=user_login.id).first().id
    db.session.add(async_operation)
    db.session.commit()
