import time
from flask import Blueprint, render_template, redirect, request, g, session, make_response, flash
import libmfa
import libuser
import libsession
# In-memory dict for login throttling: {(username, ip): [fail_count, first_fail_time, lockout_until]}
failed_logins = {}

mod_user = Blueprint('mod_user', __name__, template_folder='templates')


@mod_user.route('/login', methods=['GET', 'POST'])
def do_login():

    session.pop('username', None)

    MAX_ATTEMPTS = 5
    LOCKOUT_TIME = 300  # seconds (5 minutes)
    client_ip = request.remote_addr
    if request.method == 'POST':

        if username:
            key = (username, client_ip)
            now = time.time()
            attempts = failed_logins.get(key, [0, 0, 0])
            # Check active lockout
            if attempts[2] > now:
                flash("Too many failed login attempts. Please try again later.")
                return render_template('user.login.mfa.html')
        username = request.form.get('username')
        password = request.form.get('password')
        otp = request.form.get('otp')

        valid_user = libuser.login(username, password)

        if not valid_user:
            # Record failed login
            if username:
                fail_count, first_fail, lock_until = attempts
                if fail_count == 0 or now > first_fail + LOCKOUT_TIME:
                    # Reset fail window
                    failed_logins[key] = [1, now, 0]
                else:
                    fail_count += 1
                    lockout = 0
                    if fail_count >= MAX_ATTEMPTS:
                        lockout = now + LOCKOUT_TIME
                        flash("Too many failed login attempts. Please try again later.")
                        failed_logins[key] = [fail_count, first_fail, lockout]
                        return render_template('user.login.mfa.html')
                    failed_logins[key] = [fail_count, first_fail, 0]
            flash("Invalid user or password")
            return render_template('user.login.mfa.html')

        # On successful login, reset failed count for this user/ip
        if username:
            failed_logins.pop(key, None)
        username = valid_user
            if not libmfa.mfa_validate(username, otp):
                flash("Invalid OTP");
                return render_template('user.login.mfa.html')

        response = make_response(redirect('/'))
        response = libsession.create(response=response, username=username)
        return response

    return render_template('user.login.mfa.html')


@mod_user.route('/create', methods=['GET', 'POST'])
def do_create():

    session.pop('username', None)

    if request.method == 'POST':

        username = request.form.get('username')
        password = request.form.get('password')
        #email = request.form.get('password')
        if not username or not password:
            flash("Please, complete username and password")
            return render_template('user.create.html')

        libuser.create(username, password)
        flash("User created. Please login.")
        return redirect('/user/login')

        #session['username'] = libuser.login(username, password)

        #if session['username']:
        #    return redirect('/')

    return render_template('user.create.html')


@mod_user.route('/chpasswd', methods=['GET', 'POST'])
def do_chpasswd():

    if request.method == 'POST':

        password = request.form.get('password')
        password_again = request.form.get('password_again')

        if password != password_again:
            flash("The passwords don't match")
            return render_template('user.chpasswd.html')

        if not libuser.password_complexity(password):
            flash("The password don't comply our complexity requirements")
            return render_template('user.chpasswd.html')

        libuser.password_change(g.session['username'], password) # = libuser.login(username, password)
        flash("Password changed")

    return render_template('user.chpasswd.html')

