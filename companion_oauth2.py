import requests

from config import config

# https://auth.frontierstore.net/auth?state=42&response_type=code&approval_prompt=auto&redirect_uri=http%3A%2F%2Flocalhost%3A8080%2Foauth2%2Fcallback&client_id=b1c5c13b-2123-48cc-bfdb-a54b49f00f9b

FRONTIER_AUTH_SERVER = 'https://auth.frontierstore.net/token'
FRONTIER_LOGIN_BASE_URL = 'https://auth.frontierstore.net/auth?response_type=code&approval_prompt=auto'
CLIENT_SECRET = 'cc0e5fa9' # replace with your secret
CLIENT_ID = 'b1c5c13b-2123-48cc-bfdb-a54b49f00f9b' # replace with your client id
REDIRECT_URI = 'http://localhost:8080/oauth2/callback'


class VerificationRequired(Exception):
    def __unicode__(self):
        return _('Error: Verification failed')
    def __str__(self):
        return unicode(self).encode('utf-8')


class CredentialsError(Exception):
    def __unicode__(self):
        return _('Error: Invalid Credentials')
    def __str__(self):
        return unicode(self).encode('utf-8')


class CompanionOAuth2:
    STATE_NONE, STATE_INIT, STATE_AUTH, STATE_OK = range(4)

    def __init__(self):
        self.access_token = ''
        self.state = CompanionOAuth2.STATE_NONE
        self.cb = None

    def on_auth_callback(self, code, state):
        if(CompanionOAuth2.STATE_AUTH == self.state):
            data = dict(
                client_id=CLIENT_ID,
                client_secret=CLIENT_SECRET,
                code=code,
                redirect_uri=REDIRECT_URI,
                state=state,
                grant_type="authorization_code"
            )

            headers = {
                'Content-Type': 'application/x-www-form-urlencoded',
                'Accept': 'application/json'
            }

            r = requests.post(FRONTIER_AUTH_SERVER, data=data, headers=headers)
            response = r.json()
            self.access_token = response.get('access_token')
            refresh_token = response.get('refresh_token')

            config.set('token', refresh_token)

            self.state = CompanionOAuth2.STATE_OK
            if self.cb: self.cb()

            self.cb = None

            return r.content
        else:
            return 'Internal state not correct'

    def use_refresh_token(self):
        refresh_token = config.get('token')

        data = dict(
            client_id=CLIENT_ID,
            client_secret=CLIENT_SECRET,
            refresh_token=refresh_token,
            grant_type="refresh_token"
        )

        headers = {
            'Content-Type': 'application/x-www-form-urlencoded',
            'Accept': 'application/json'
        }

        response = requests.post(FRONTIER_AUTH_SERVER, data=data, headers=headers)
        if 200 != response.status_code:
            raise VerificationRequired

        response = response.json()
        self.access_token = response.get('access_token')
        refresh_token = response.get('refresh_token')

        config.set('token', refresh_token)
        self.state = CompanionOAuth2.STATE_OK

    def get_access_token(self):
        if CompanionOAuth2.STATE_OK != self.state:
            raise CredentialsError()

        return self.access_token

    def start_auth(self, callback):
        self.state = CompanionOAuth2.STATE_AUTH
        self.cb = callback
        return FRONTIER_LOGIN_BASE_URL + '&state=42' + '&redirect_uri=http%3A%2F%2Flocalhost%3A8080%2Foauth2%2Fcallback' + '&client_id=' + CLIENT_ID


companionoauth2 = CompanionOAuth2()


def oauth2_webapp(webapp):
    @webapp.route('/callback')
    def callback(request):
        if ('state' in request.args) and ('code' in request.args):
            state = request.args['state']
            code = request.args['code']
            return companionoauth2.on_auth_callback(code, state)
        else:
            return 'Something went wrong'

    @webapp.route("/")
    def hi(request):
        return "Hi"
