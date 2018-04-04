from hardwarecheckout import app
from hardwarecheckout import config
from hardwarecheckout.models.user import *
from hardwarecheckout.utils import verify_token, generate_auth_token
import requests
import datetime
import json
from urlparse import urljoin
from hardwarecheckout.forms.login_form import LoginForm
from mlh_oauth import MLHSignIn
from flask import (
    flash,
    redirect,
    render_template,
    request,
    url_for
)

@app.route('/login')
def login_page():
    return MLHSignIn().authorize()

@app.route('/callback/mlh')
def oauth_callback():
    if 'jwt' in request.cookies:
        token = verify_token(request.cookies['jwt'])
        if token is not None:
            return redirect('/inventory')

    mlh_user = MLHSignIn().callback()

    if mlh_user is None or mlh_user.id is None:
        flash('Authentication failed.')
        return redirect('/inventory')

    if User.query.filter_by(email=mlh_user.email).count() == 0:
        admin = email in config.ADMINS
        user = User(email, admin)
        db.session.add(user)
        db.session.commit()

    # generate token since we cut out quill
    token = generate_auth_token(mlh_user.email)
    response = app.make_response(redirect('/inventory'))
    response.set_cookie('jwt', token.encode('utf-8'))

    return response

@app.route('/logout')
def logout():
    """Log user out"""
    response = app.make_response(redirect('/'))
    response.set_cookie('jwt', '')
    return response
