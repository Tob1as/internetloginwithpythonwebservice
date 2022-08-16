#!/usr/bin/env python
#-*- coding: utf-8 -*-

"""
Webservice for the login of the device on which it is running.

Internet-Login/Logout for dormitory network of the Johannes-Gutenberg-University Mainz and Studierendenwerk Mainz.
"""

import os
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from http import HTTPStatus
import ssl
import requests
from urllib.parse import parse_qs, urlparse
from cgi import parse_header, parse_multipart
from bs4 import BeautifulSoup
import platform
import subprocess
import fnmatch
import json

HTTPD_HOST = str(os.environ.get('HTTP_HOST', '0.0.0.0'))
HTTPD_PORT = int(os.environ.get('HTTP_PORT', 8000))
HTTPD_BASEPATH = str(os.environ.get('HTTPD_BASEPATH', ''))
HTTPD_SSL_ENABLE = int(os.environ.get('HTTPD_SSL_ENABLE', 0))

STATUS_HOST = str(os.environ.get('STATUS_HOST', '134.93.178.2'))

WEBSITE_TITLE="Wohnheime Mainz - Internet Login/Logout"
WEBSITE_FAVICON_BASE64="R0lGODlhEAAQAPcAAMfQAP///sPNAMTOAB9AjMLMAMnRAMTNAM7VAB4+i8vTAPv758XOAP398uDkWP///f/++rbC2P799dvgQPj42Pn52fn53Pr63dHYEs/WBdPZE+7woa662vj52ujs9vPzt87VAvn52hk6if799tXbHfn5zO3votXaJOToeubpgf398NjdMPz76N/jTuPnbwAbefb30KGr0ebqiPDxqfr64AAXe/H08tfeNfX2nP3+/hU2i87T6gASdgAOc+vumOzthwAbeomXw/j5/AAbe+nsh+zumd7j9O/xrNPZF+7voQ4wg///+wASegAefeztmPT1nertmuvtlO/xq/7+9+Lmde3vnsnP5MTM5NPZFeLla8bPAHGErwUpfgAfe9neQRc4h8/WD+rrhejrg+vsjvj42tbcKM7VBvb2yvT1w9neNgAcev398w8vgiBAjNzhSfHyrx09i8nSAPf41/r61bbA2Pb2yd/kU8vTAebqfCdElx09ipWfyubpfO/vnqGtxePncNbbH/X29v///wAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACH/C1hNUCBEYXRhWE1QPD94cGFja2V0IGJlZ2luPSLvu78iIGlkPSJXNU0wTXBDZWhpSHpyZVN6TlRjemtjOWQiPz4gPHg6eG1wbWV0YSB4bWxuczp4PSJhZG9iZTpuczptZXRhLyIgeDp4bXB0az0iQWRvYmUgWE1QIENvcmUgNS4zLWMwMTEgNjYuMTQ1NjYxLCAyMDEyLzAyLzA2LTE0OjU2OjI3ICAgICAgICAiPiA8cmRmOlJERiB4bWxuczpyZGY9Imh0dHA6Ly93d3cudzMub3JnLzE5OTkvMDIvMjItcmRmLXN5bnRheC1ucyMiPiA8cmRmOkRlc2NyaXB0aW9uIHJkZjphYm91dD0iIiB4bWxuczp4bXA9Imh0dHA6Ly9ucy5hZG9iZS5jb20veGFwLzEuMC8iIHhtbG5zOnhtcE1NPSJodHRwOi8vbnMuYWRvYmUuY29tL3hhcC8xLjAvbW0vIiB4bWxuczpzdFJlZj0iaHR0cDovL25zLmFkb2JlLmNvbS94YXAvMS4wL3NUeXBlL1Jlc291cmNlUmVmIyIgeG1wOkNyZWF0b3JUb29sPSJBZG9iZSBQaG90b3Nob3AgQ1M2IChNYWNpbnRvc2gpIiB4bXBNTTpJbnN0YW5jZUlEPSJ4bXAuaWlkOjdCNTBFMjc5NjgyMzExRTQ4MkQ2QzI4MTc5QjlCMTE5IiB4bXBNTTpEb2N1bWVudElEPSJ4bXAuZGlkOjdCNTBFMjdBNjgyMzExRTQ4MkQ2QzI4MTc5QjlCMTE5Ij4gPHhtcE1NOkRlcml2ZWRGcm9tIHN0UmVmOmluc3RhbmNlSUQ9InhtcC5paWQ6N0I1MEUyNzc2ODIzMTFFNDgyRDZDMjgxNzlCOUIxMTkiIHN0UmVmOmRvY3VtZW50SUQ9InhtcC5kaWQ6N0I1MEUyNzg2ODIzMTFFNDgyRDZDMjgxNzlCOUIxMTkiLz4gPC9yZGY6RGVzY3JpcHRpb24+IDwvcmRmOlJERj4gPC94OnhtcG1ldGE+IDw/eHBhY2tldCBlbmQ9InIiPz4B//79/Pv6+fj39vX08/Lx8O/u7ezr6uno5+bl5OPi4eDf3t3c29rZ2NfW1dTT0tHQz87NzMvKycjHxsXEw8LBwL++vby7urm4t7a1tLOysbCvrq2sq6qpqKempaSjoqGgn56dnJuamZiXlpWUk5KRkI+OjYyLiomIh4aFhIOCgYB/fn18e3p5eHd2dXRzcnFwb25tbGtqaWhnZmVkY2JhYF9eXVxbWllYV1ZVVFNSUVBPTk1MS0pJSEdGRURDQkFAPz49PDs6OTg3NjU0MzIxMC8uLSwrKikoJyYlJCMiISAfHh0cGxoZGBcWFRQTEhEQDw4NDAsKCQgHBgUEAwIBAAAh+QQAAAAAACwAAAAAEAAQAAAI1AAFCRxIsKCgM3c0GAAAgMXANVmg+DCxIA0CFRSo/AgwMMAMMHEAKJgAoIJBglNIKCByYMPAQBz20CFoZkWRAlEE2mADhEuPCAIvDBCDR0AfQTnyNGmTQIkOIYJKCHhjh8ETQVbUEICTQEQXD4LmDKjigAEOQTt4fCGgh0kQgQ0MtPgDwImgAH6GvKixZeADBEjGDJAy0EiMKwUBZfhQoMNJgmFA1BFA44HAJRwFoUlxJIQLNw1unMBSxgsfCAIlyMCg5YADgQvkwCAzwqAFFEkePw4IADs=" # STWMZ
#WEBSITE_FAVICON_BASE64="AAABAAEAEBAAAAAAAABoBQAAFgAAACgAAAAQAAAAIAAAAAEACAAAAAAAAAEAAAAAAAAAAAAAAAEAAAAAAAAsA70AKyO+ACMGtQAjBbgAKAK4ACUFuAAqArgAKwK4ACoBuwAtMLsALAW4AC0FuAA/Q8cAIwO2AC4DvgAuB7sAKwO2ACgFuQAqBbkAKAS8ACwFuQAmB7wAKgS8ACYDtwAoA7cAJgK6ACoDtwAoAroAKxG5ACMbtgAmBboAKAW6ACYCsgAmBL0AJAG1ACgBtQAnIbYAMAW6ACQDuAAcDbUAJgO4AC0HvQAoB7UAJga4ACwDuAAoBrgALgO4ACAFswArArsALAK7AC4CuwAsIrwAKwG+ACsFuwAtBbsAJAe2ACYHtgApA7kAKwO5ACwDuQAtBrkAJwG3ACkBtwAqGb4AKwS3AB4GsgArBroALQa6ACkFvQAwI7sAKwW9ADMtwABDS8YAJwS4ACMHuAApBLgALQG4AC0huQArBLgAJwO7ACkDuwAlGLoAJQK2ACIFtgAnArYAMQa7AP///wAnBLkAKQe5AC0EuQAsA7wALAa8ACcGtAAuBrwAKQa0ACUFtwApBbcAKRO5ACoBugAqBLoALAS6AC0EugAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAMGMGUDk5BAQxMAZOOQQ5EghDWldjPTo6ThAbV2M5BFQGQklkNgY6NhNJGUtkZGQEUBROT05OThQrVlMwZGRjORoBRRQ5FhQRUFYqQGU6JSwfVlYvAFAXQQ5WPEseS04ROiFWTWRWVlYcVmBWVlZWB1cWVlFWSmFWR1YFVg0VVmAGZFYnVjkwPyRWXlZTUlY0OU5WHVYMHwkzVilWOCZWXA9jVkgmVlZWRFYCVi5ZVlswWFlCC0YYLUJWAyVOOlALIxMRE0xPBgpQVjc7ZFo6H1ooVV9kE1AiZVYOIGNaZD45ZWJlZGNkFElELGNjYzo1WAY5MmRkZWVONmQKTk5kXQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=" # Uni-Mainz

print(f"LOAD ENV: HTTPD_HOST={HTTPD_HOST} ; HTTPD_PORT={HTTPD_PORT} ; HTTPD_BASEPATH={HTTPD_BASEPATH} ; HTTPD_SSL_ENABLE={HTTPD_SSL_ENABLE} ; STATUS_HOST={STATUS_HOST}")

# current time
def currenttime():
    t = time.localtime()
    current_time = time.strftime("%Y-%m-%d %H:%M:%S", t)
    return current_time

# set html-header 
def set_headers(self):
    self.send_response(HTTPStatus.OK.value)  # 200
    self.send_header("Content-type", "text/html")
    #self.send_header('Access-Control-Allow-Origin', '*')
    self.end_headers()

# set html content before "body" content
def html_beginn(self):
    self.wfile.write(bytes("<!DOCTYPE html>", "utf-8"))
    self.wfile.write(bytes("<html>", "utf-8"))
    self.wfile.write(bytes("<head>", "utf-8"))
    self.wfile.write(bytes(f"<meta charset='utf-8'><meta name='viewport' content='width=device-width, initial-scale=1'><title>{WEBSITE_TITLE}</title>", "utf-8"))
    self.wfile.write(bytes(f"<link rel='shortcut icon' type='image/x-icon' sizes='16x16' href='data:image/x-icon;base64,{WEBSITE_FAVICON_BASE64}' />", "utf-8"))
    self.wfile.write(bytes("</head>", "utf-8"))
    self.wfile.write(bytes("<body>", "utf-8"))

# set html content after "body" content
def html_end(self):
    self.wfile.write(bytes("</body>", "utf-8"))
    self.wfile.write(bytes("</html>", "utf-8"))

# parse post
def parse_POST(self):
    ctype, pdict = parse_header(self.headers.get('content-type'))
    if ctype == 'multipart/form-data':
        pdict['boundary'] = bytes(pdict['boundary'], 'utf-8')
        postvars = parse_multipart(self.rfile, pdict)
    elif ctype == 'application/x-www-form-urlencoded':
        length = int(self.headers['content-length'])
        postvars = parse_qs(self.rfile.read(length).decode('utf8'),keep_blank_values=1)
    else:
        postvars = {}
    #print(postvars)  # use only for debug on development system!!
    return postvars

# ping: check host is online/offline (Requirement package on host: debian/ubuntu->iputils-ping, alpine->iputils)
def ping(host):
    #param = '-n' if platform.system().lower()=='windows' else '-c' # count
    param = '-w' # timeout
    command = ['ping', param, '1', host]
    return subprocess.call(command, stdout=subprocess.PIPE) == 0

# GET: error page
def error_page(self):
    # httpd output
    self.send_response(HTTPStatus.NOT_FOUND.value) # 404
    #self.send_header('Access-Control-Allow-Origin', '*')
    self.send_header('Content-type','text/html')
    self.end_headers()
    html_beginn(self)
    self.wfile.write(bytes("404 - Not Found! :-P", "utf-8"))
    html_end(self)

# GET: healthcheck
def get_healthcheck(self):
    # httpd output
    self.send_response(HTTPStatus.OK.value) # 200
    self.send_header('Content-type','text/plain')
    self.end_headers()
    #self.wfile.write(bytes("It Works!", "utf-8"))

# GET: status
def get_status(self):
    current_time = currenttime()
    #print("%s - DEBUG: Call GET-Request: %s" % (current_time, self.path))
    
    # check online status
    response = ping(STATUS_HOST)
    if response==True:
        status="Online! :-)"
        statusjson="Online"
    else:
        status="Offline! :-("
        statusjson="Offline"
    print("%s - INFO: Status: %s" % (current_time, status))

    try:
        param = parse_qs(urlparse(self.path).query)['format'][0]
    except:
        param = ''
    
    if param=='json':
        # inital json
        #jsondata={}
        # json content
        jsondata= {
            'Time' : current_time,
            'Status': statusjson
        }

        # httpd output as json
        self.send_response(HTTPStatus.OK.value)  # 200
        self.send_header("Content-type", "application/json")
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
        self.wfile.write(json.dumps(jsondata).encode('utf-8'))
    else:
        # httpd output as html
        set_headers(self)
        html_beginn(self)
        #self.wfile.write(bytes(f"<p>Current time: {current_time}</p>", "utf-8"))
        #self.wfile.write(bytes("<p>Request: %s</p>" % self.path, "utf-8"))
        self.wfile.write(bytes(f"<p>Status: {status}</p>", "utf-8"))
        #self.wfile.write(bytes(f"<p><i>Time: {current_time}</i></p>", "utf-8"))
        html_end(self)
    

# GET: login
def get_login(self):
    current_time = currenttime()
    #print("%s - DEBUG: Call GET-Request: %s" % (current_time, self.path))

    # httpd output
    set_headers(self)
    html_beginn(self)
    self.wfile.write(bytes("<p>Hello, now login this Device with your credentials:</p>", "utf-8"))
    self.wfile.write(bytes("<form name='inputdata' method='POST' enctype='application/x-www-form-urlencoded' action=''>", "utf-8"))
    self.wfile.write(bytes("<table id='table' style='border: 0;'>", "utf-8"))
    self.wfile.write(bytes("<tr><td style='text-align: left;'>Username</td><td><input type='text' id='user' name='user' value='' size='20' maxlength='8' /></td></tr>", "utf-8"))
    self.wfile.write(bytes("<tr><td style='text-align: left;'>Password</td><td><input type='password' id='pass' name='pass' value='' size='20' maxlength='40' /></td></tr>", "utf-8"))
    self.wfile.write(bytes("</table>", "utf-8"))
    self.wfile.write(bytes("<p><input type='submit' name='submit' value='Login' /></p>", "utf-8"))
    self.wfile.write(bytes("</form>", "utf-8"))
    html_end(self)

# GET: logout
def get_logout(self):
    current_time = currenttime()
    #print("%s - DEBUG: Call GET-Request: %s" % (current_time, self.path))

    # httpd output
    set_headers(self)
    html_beginn(self)
    #self.wfile.write(bytes(f"<b> Current time: {current_time}", "utf-8"))
    #self.wfile.write(bytes("<p>Request: %s</p>" % self.path, "utf-8"))
    self.wfile.write(bytes("<form name='inputdata' method='POST' enctype='application/x-www-form-urlencoded' action=''>", "utf-8"))
    self.wfile.write(bytes("<p><input type='submit' name='submit' value='Logout' /></p>", "utf-8"))
    self.wfile.write(bytes("</form>", "utf-8"))
    html_end(self)

# POST: login
def post_login(self):
    current_time = currenttime()
    #print("%s - DEBUG: Call GET-Request: %s" % (current_time, self.path))

    # get vars from POST
    postvars = parse_POST(self)
    #print(postvars)  # use only for debug on development system!!
    username = postvars.get('user')[0]
    password = postvars.get('pass')[0]
    #submit = postvars.get('submit')[0]

    payload = {
        'user': username,
        'pass': password
    }
    response = requests.post('https://login.wohnheim.uni-mainz.de/cgi-bin/login-cgi', data=payload)
    #print("%s - DEBUG: Login-Statuscode: %s ; Login-Response: %s" % (current_time, response.status_code, response.content))

    soup = BeautifulSoup(response.content, 'html.parser')
    #print("%s - DEBUG: Login-Response (Pretty): %s" % (current_time, soup.prettify()))
    soupreturn = soup.find(id='content').get_text().replace(' ', '').strip().split(".",1)[0]
    #print("%s - DEBUG: Login-Response (var: soupreturn): %s" % (current_time, soupreturn))
    if soupreturn == 'LogInsuccessful':
        logininfo="Login success! :-)"
    elif soupreturn == 'LogInunsuccessful':
        logininfo="Login failed! :-("
    else: 
        logininfo = "Login Status unknown! :-S"
    #print("%s - DEBUG: Login-Text (var: logininfo): %s" % (current_time, logininfo))

    print("%s - INFO: %s -> User: %s" % (current_time, logininfo, username))

    # httpd output
    set_headers(self)
    html_beginn(self)
    self.wfile.write(bytes(f"<p>{logininfo} (Username: {username})</p>", "utf-8"))
    html_end(self)

# POST: logout
def post_logout(self):
    current_time = currenttime()
    #print("%s - DEBUG: Call GET-Request: %s" % (current_time, self.path))

    # get vars from POST
    postvars = parse_POST(self)
    #print(postvars)  # use only for debug on development system!!
    #submit = postvars.get('submit')[0]

    payload = {
        'command': 'logout'
    }
    response = requests.post('https://login.wohnheim.uni-mainz.de/cgi-bin/logout.cgi', data=payload)
    #print("%s - DEBUG: Logout-Statuscode: %s ; Logout-Response: %s" % (current_time, response.status_code, response.content))

    soup = BeautifulSoup(response.content, 'html.parser')
    #print("%s - DEBUG: Logout-Response (Pretty): %s" % (current_time, soup.prettify()))
    soupreturn = soup.find('td').get_text().replace(' ', '').strip()
    #print("%s - DEBUG: Logout-Response (var: soupreturn): %s" % (current_time, soupreturn))
    if soupreturn == 'YourIPhasbeensuccessfullydisabled.':
        logoutinfo="Logout success! :-O"
    else:
        logoutinfo = "Logout Status unknown! :-S"
    #print("%s - DEBUG: Logout-Text (var: logoutinfo): %s" % (current_time, logoutinfo))

    # httpd output
    set_headers(self)
    html_beginn(self)
    self.wfile.write(bytes(f"<p>{logoutinfo}</p>", "utf-8"))
    html_end(self)

class InternetServer(BaseHTTPRequestHandler):

    def do_GET(self):
        if self.path == '/healthcheck':
            get_healthcheck(self)
        #elif self.path == HTTPD_BASEPATH + '/status':
        #    get_status(self)
        elif fnmatch.fnmatch(self.path, HTTPD_BASEPATH + '/status*'):
            get_status(self)
        elif self.path == HTTPD_BASEPATH + '/login':
            get_login(self)
        elif self.path == HTTPD_BASEPATH + '/logout':
            get_logout(self)
        else:
            error_page(self)

    def do_POST(self):
        if self.path == HTTPD_BASEPATH + '/login':
            post_login(self)
        elif self.path == HTTPD_BASEPATH + '/logout':
            post_logout(self)
        else:
            error_page(self)

if __name__ == "__main__":        
    httpd = HTTPServer((HTTPD_HOST, HTTPD_PORT), InternetServer)

    # https/ssl
    if HTTPD_SSL_ENABLE and HTTPD_SSL_ENABLE == 1 and os.path.exists('ssl.crt') and os.path.exists('ssl.key'):
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.set_ciphers('EECDH+AESGCM:EDH+AESGCM')
        ctx.check_hostname = False
        ctx.load_cert_chain(certfile='ssl.crt', keyfile='ssl.key')
        httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
        HTTPD_SCHEME="https"
    else:
        HTTPD_SCHEME="http"

    print("Server started %s://%s:%s at %s" % (HTTPD_SCHEME, HTTPD_HOST, HTTPD_PORT, currenttime()))
    print("Status-URL:  %s://localhost:%s%s/status"  % (HTTPD_SCHEME, HTTPD_PORT, HTTPD_BASEPATH))
    print("Login-URL:  %s://localhost:%s%s/login"  % (HTTPD_SCHEME, HTTPD_PORT, HTTPD_BASEPATH))
    print("Logout-URL: %s://localhost:%s%s/logout" % (HTTPD_SCHEME, HTTPD_PORT, HTTPD_BASEPATH))

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass

    httpd.server_close()
    print("Server stopped.")
