import json
from flask import redirect, url_for, request, current_app, session
from rauth import OAuth1Service, OAuth2Service
from hardwarecheckout import config

class MLHUser():
    def __init__(self, id, email,
                 level_of_study, school, major,
                 shirt_size, dietary_restrictions, special_needs):
        self.id = id
        self.email = email
        self.level_of_study = level_of_study
        self.school = school
        self.major = major
        self.shirt_size = shirt_size
        self.dietary_restrictions = dietary_restrictions
        self.special_needs = special_needs

class MLHSignIn(object):
    def __init__(self):
        credentials = config.OAUTH_CREDENTIALS
        self.consumer_id = credentials["id"]
        self.consumer_secret = credentials["secret"]
        self.service = OAuth2Service(
            name="mlh",
            client_id = self.consumer_id,
            client_secret = self.consumer_secret,
            authorize_url='https://my.mlh.io/oauth/authorize',
            access_token_url='https://my.mlh.io/oauth/token',
            base_url='https://my.mlh.io/'
        )

        # Permission scopes for user data requests
        # Possible scopes at https://my.mlh.io/docs#scopes_reference
        self.scopes = [
            'email',     # Email address
            'education', # Level of study, school, major
            'event'      # Shirt size, dietary restrictions, special needs
        ]

    def get_callback_url(self):
        return url_for("oauth_callback", _external=True)

    def authorize(self):
        return redirect(self.service.get_authorize_url(
            response_type='code',
            redirect_uri=self.get_callback_url())
            scopes='+'.join(self.scopes)
        )

    def callback(self):
        if 'code' not in request.args:
            return None

        oauth_session = self.service.get_auth_session(
            data = {
                'code': request.args['code'],
                'redirect_uri': self.get_callback_url(),
                'grant_type': 'authorization_code'
            },
            decoder = json.loads
        )
        me = oauth_session.get('/api/v2/user.json').json()
        medata = me.get('data')

        return MLHUser(
            medata.get('id'),
            medata.get('email'),
            medata.get('level_of_study'),
            medata.get('school'),
            medata.get('major'),
            medata.get('shirt_size'),
            medata.get('dietary_restrictions'),
            medata.get('special_needs')
        )
