import time
import sys
import pprint, getopt, os, re
import string, random, glob, subprocess, pickle, tempfile

SCRIPT_VERSION = "0.2.1"

PY_VERSION_MAJOR = sys.version_info.major
PY_VERSION_MINOR = sys.version_info.minor

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
CURRENT_FILE = os.path.basename(__file__)
SESSION_DIR = tempfile.gettempdir()     # Session dir will be temp file dir.

# This is the configuration file name.
CONFIG_FILE_NAME = 'config.al'

# Session file extension.
SESSION_FILE_EXT = '.al.session'

# This is the config file path
CONFIG_PATH = os.path.join(CURRENT_DIR, CONFIG_FILE_NAME)

# All variable that will be used for request.
REFERRER_LOGIN = "10.10.0.1/24online/webpages/client.jsp",
REFERRER_LOGOUT = "http://10.10.0.1/24online/servlet/E24onlineHTTPClient"
SUBMIT_URL = "http://10.10.0.1/24online/servlet/E24onlineHTTPClient"

# All string for final message
FINAL_MESSAGES = {
    'login': 'We have been able to log you in.',
    'logout': 'You are now logged out.',
    'renew': 'Please renew your package.',
    'unknown': 'Well, Error getting message, normally you are logged in or try to use browser.',
    'wup': 'Wrong username/password, please reconfigure.'
}

# Regex for session name.
REGEX_SESSION_FILE_NAME = r'[a-zA-Z0-9]{30}' + SESSION_FILE_EXT


def getStatusFromPage(page):

    # we are gonna check ability for every messages one by one.
    # To do that store all the patterns in a variable.
    # TODO: more status to be updated.

    patterns = {
        'login':    b'<([^\S]|)font[^\S](.*)>Remaining Time:',
        'renew':    b'<([^\S]|)font[^\S](.*)>Please renew your',
        'logout':   b'<([^\S]|)font[^\S](.*)>You have successfully logged off',
        'wup':      b'<([^\S]|)font[^\S](.*)>Wrong username'
    }

    iterItems = patterns.iteritems() if PY_VERSION_MAJOR < 3 else patterns.items()

    for status, regex in iterItems:
        if re.search(regex, page, re.I) is not None:
            return status

    # if not thing matched
    return 'unknown'


###
# Config file functions
###
def createConfigFile():
    # file = open(filePath, 'w');

    # Store the username and password
    username = Input("Please enter your username: ")
    password = Input("Please enter your password: ")

    # Now create the file.
    file = open(CONFIG_PATH, 'w')
    file.writelines(['username=' + username, '\n', 'password=' + password])
    file.close()


def getInfoFromConfig():
    """
    Gets the username and password from config files.
    :return:
    """
    # First get the  configuration file.
    file = open(CONFIG_PATH, 'r')
    configs = file.read()
    file.close()

    # Now check if the `username` or `password` parameter is available in config file.
    # First match the `username`
    match_username = re.search(r'username(?:[^\S]|)=(?:[^\S]|)(.+)(:?[^\S]|)', configs, re.I)
    match_password = re.search(r'password(?:[^\S]|)=(?:[^\S]|)(.+)(:?[^\S]|)', configs, re.I)

    if match_password is None or match_username is None:
        raise Exception("Your configurations file is broken, type ./" + CURRENT_FILE + " -c to reconfigure.")

    return {
        'username': match_username.group(1).strip(),
        'password': match_password.group(1).strip(),
    }


###
# End of config file functions
###


###
# Login and log out functions
###
def getLoginVars():
    """
    This method gets the log in vars.
    """
    # get username and password.
    info = getInfoFromConfig()

    # Its now time to create vars.
    return {
        'mode': "191",
        'isAccessDenied': "null",
        'url': "10.10.0.1/24online/webpages/client.jsp",
        'message': "You are now Log In",
        'checkClose': "0",
        'sessionTimeout': "0.0",
        'guestmsgreq': "false",
        'username': info['username'],
        'password': info['password'],
    }


def getLogoutVars():
    """
    This method helps to get log out vars.
    :return:
    """
    # get username and password.
    info = getInfoFromConfig()

    return {
        'mode':             "193",
        'isAccessDenied':   "false",
        'url':              "10.10.0.1/24online/webpages/client.jsp",
        'message':          "You are now log out.",
        'checkClose':       "1",
        'sessionTimeout':   "-1.0",
        'guestmsgreq':      "false",
        'loggedinuser':     info['username'],
        'username':         info['username']
    }


def loginUser():
    """
    Logs in users.
    :return:
    """
    print("Sending request for logging in..")
    # Check if any previous session is available, then kill and delete them.
    files = getAllSessionFiles()
    if files:
        print("Deleting session files.")
        deleteAllSessionFiles(files)

    time.sleep(3)

    login_vars = getLoginVars()
    page = sendRequest(login_vars, REFERRER_LOGIN)

    # Get page status.
    status = getStatusFromPage(page)
    # Now print the final message from page.
    print(FINAL_MESSAGES[status])

    # Now work with process.
    if status == 'login':
        # First create the new process
        process = Process()
        Process.write_session({
            'username': login_vars['username'],
            'password': login_vars['password']
        }, process.getProcessId())  # Session name will be valid process id.

        # Now start the process.
        process.startProcess()


def logoutUser():
    """
    Logs out users.
    :return:
    """
    print("Sending request for logging out..")
    # get the session files.
    files = getAllSessionFiles()
    if files:
        deleteAllSessionFiles(files)

    time.sleep(3)

    page = sendRequest(getLogoutVars(), REFERRER_LOGOUT)

    # Now print the final message from page.
    print(FINAL_MESSAGES[getStatusFromPage(page)])


###
# End of login logout functions
###


def sendRequest(svars, referer):
    """
    This function helps to send request.
    :param svars:
    :param referer:
    :return:
    """
    en = urlen(svars)
    req = Req(SUBMIT_URL, en)
    req.add_header('referer', str(referer))
    res = urlo(req)
    return res.read()


###
# Process and session files method and classes.
###

def getAllSessionFiles():
    """
    This method will help to get all the Session files that are available.
    :return:
    """
    # This statement matches for the session files
    files = [f for f in os.listdir(SESSION_DIR) if re.match(REGEX_SESSION_FILE_NAME, f)]

    all_files = []
    for file in files:
        all_files.append(os.path.join(SESSION_DIR, file))

    return all_files


def deleteAllSessionFiles(files):
    """
    This method will help with deleting any files.
    :param files:
    :return:
    """
    if not files:
        sys.exit()
    else:
        for file in files:
            os.remove(file)


class Process:
    """
    This class helps to manage process
    """
    __processId = ''    # Store the session name.
    __pickle = None     # Store the pickle object.
    __vars = {}         # Stores all vars.

    def __init__(self, process_id=None):

        if process_id is not None:
            self.__processId = process_id
        else:
            self.__processId = Process.generateRandomString(30)

    def getProcessId(self):
        return self.__processId

    def startProcess(self):
        # proc.py path
        path_script = os.path.join(CURRENT_DIR, 'proc.py')

        self.__pickle = subprocess.Popen(sys.executable + " " + path_script + " " + self.__processId, shell=True)
        print(self.__pickle.pid)

    def killProcess(self):
        # get process
        self.__pickle.kill()

    @staticmethod
    def generateRandomString(size):
        """
        This method helps you to generate random string.
        :param size:
        :return:
        """
        return ''.join(
            random.choice(string.ascii_uppercase + string.digits + string.ascii_lowercase) for _ in range(size))

    @staticmethod
    def write_session(session, session_unique_name):

        file = open(os.path.join(SESSION_DIR, session_unique_name + SESSION_FILE_EXT), 'wb')
        pickle.dump(session, file)
        file.close()

    @staticmethod
    def read_session(session_file):
        file = open(os.path.join(SESSION_DIR, session_file), 'rb')
        session = pickle.load(file)
        file.close()
        return session

###
# End of process and Session files method and classes.
###


# Python 2 AND 3 Compatibility work started here #
def Input(str):
    if PY_VERSION_MAJOR < 3:
        return raw_input(str)
    else:
        return input(str)


def Req(url, vars=None):
    if PY_VERSION_MAJOR < 3:
        from urllib2 import Request
    else:
        from urllib.request import Request
    return Request(url, vars)


def urlo(req):
    if PY_VERSION_MAJOR < 3:
        from urllib2 import urlopen
    else:
        from urllib.request import urlopen
    return urlopen(req)


def urlen(vars):
    if PY_VERSION_MAJOR < 3:
        from urllib import urlencode
        return urlencode(vars)
    else:
        from urllib.parse import urlencode
        return urlencode(vars).encode('UTF-8')


# END OF Python 2 AND 3 Compatibility work #

def printHelp():
    print(
        """
           PMPL-Autologin version %s
           Please report bugs to our github page: https://github.com/rajajoddar/pmpl-autologin
           Contributors: Raja Joddar & Akash Bose

           example: %s -l

           -l --log-in      send a log in request.
           -L --log-out     send a log out request.
           -c               configure again for username and password.
           -h --help        show this help.

        """ % (SCRIPT_VERSION, CURRENT_FILE)
    )


def checkPythonVersion():
    if PY_VERSION_MAJOR < 3 and PY_VERSION_MINOR < 7:
        print("Python version 2.7 or higher is require.")
        sys.exit()


def __main__(argv):

    # First check if the user has installed required python version.
    checkPythonVersion()

    # Now check if the configuration file exists.
    # If not then just simply create one.
    if os.path.isfile(CONFIG_PATH) is not True:
        print("\nWelcome to PMPL-AUTOLOGIN.")
        print("We need to configure your username and password.\n")
        print("Warning: write your username and password with maintained caps.\n")
        createConfigFile()

        # check if the user want to log in right now.
        if Input("Do you want to get login now? (y/n)").lower()[0] == 'y':
            loginUser()
            sys.exit()
        else:
            sys.exit()  # Exit the script as user do not want to get logged in

    # Now its time to work with arguments
    opts, args = getopt.getopt(argv, "chlL", ["log-in", "log-out"])

    if len(argv) > 1:
        print("Please use only one option.")
        sys.exit()
    elif len(argv) < 1:
        printHelp()
        sys.exit()

    for opt, arg in opts:

        if opt == '-c':
            print("Welcome to configuration.")
            createConfigFile()
            sys.exit()

        elif opt == '-h' or opt == '--help':
            printHelp()

        elif opt == '-L' or opt == '--log-out':
            logoutUser()

        elif opt == '-l' or opt == '--log-in':
            loginUser()


if __name__ == "__main__":
    try:
        __main__(sys.argv[1:])
    except (KeyboardInterrupt, EOFError) as e:
        print("\n\nAs you command, exiting in the middle..")
    except getopt.GetoptError:
        printHelp()
    except Exception as ex:
        print("\n\nError: " + str(ex))
