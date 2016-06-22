import os
import re
import sys
import time

from autologin import Process
from autologin import getLoginVars
from autologin import sendRequest
from autologin import REFERRER_LOGIN
from autologin import SESSION_DIR

TIME_SLEEP = 60 * 15

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
CURRENT_FILE = os.path.basename(__file__)

# LIVE_REQ_URL1 = 'http://10.10.231.231/24online/webpages/liverequest.jsp'
# LIVE_REQ_URL2 = 'http://10.10.231.231/24online/servlet/E24onlineHTTPClient'
# REFERRER = "http://10.10.0.1/24online/servlet/E24onlineHTTPClient"
# Process file extension.
SESSION_FILE_EXT = '.al.session'


def __main__(argv):
    if len(argv) < 1 and re.match(r'[A-Za-z0-9]{30}', argv[0]) is None:
        print("station file name is not valid.")

    time.sleep(TIME_SLEEP)

    # Now check if the session file is actually exits.
    path_script = os.path.join(SESSION_DIR, argv[0] + SESSION_FILE_EXT)
    if not os.path.isfile(path_script):
        sys.exit()

    # Read for session data.
    try:
        session = Process.read_session(path_script)
    except IOError as ex:
        sys.exit()

    # After trying few things..
    # I am gonna resend the login request at every  15 minutes
    login_vars = getLoginVars()
    login_vars['username'] = session['username']
    login_vars['password'] = session['password']
    sendRequest(login_vars, REFERRER_LOGIN)

    # Now create a new Process.
    process = Process(argv[0])
    process.startProcess()


if __name__ == '__main__':
    __main__(sys.argv[1:])


