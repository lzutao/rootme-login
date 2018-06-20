#!/usr/bin/env python
from __future__ import print_function
from builtins import input

import getpass # Portable password input
import sys
import logging
import pickle

import requests
import lxml.html

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s %(name)-12s %(levelname)-8s %(message)s',
    )

log = logging.getLogger(__file__)

def input_login():
    login = input("Login: ")
    return login

def input_password():
    passwd = getpass.getpass('Password: ')
    return passwd

class Registration():
    """This class provide way to login in root-me.org"""
    def __init__(self, login_name, passwd):
        self.login_name = login_name
        self.passwd = passwd

        self.session = requests.Session()
        self.session.headers.update(Registration.HEADERS)

        # In name : value
        self.login_data = {
            'var_login': self.login_name,
            'password': self.passwd,

            'page': 'login',
            'lang': 'en',
            'ajax': '1',
            'formulaire_action': 'login',
            'formulaire_action_args': None,
            }

    def _get_request(self, url):
        r = Registration.request(self.session.get, url)
        return r

    def _login(self, tree):
        """_login(self, tree) -> requests.models.Response

        Send login_data and save cookies if succeed.
        Return a respone from that post request.
        """
        self.login_data['formulaire_action_args'] = Registration.get_value_from_name(tree, 'formulaire_action_args')
        r = Registration.request(self.session.post, Registration.URL_LOGIN, data=self.login_data)
        if self.session.cookies._cookies:
            log.info('Login success ...')
            log.info("Saving cookies in %r ..." % Registration.COOKIE_FILE)
            Registration.cookies_save(self.session, Registration.COOKIE_FILE)
        else:
            Registration.write_html(r.content)
            log.info('status_code: %d' % r.status_code)
            log.info('URL: %r' % r.url)
            log.error('Something wrong! Cannot connect!')
        return r

    def login(self):
        """login(self) -> lxml.html.HtmlElement

        Return html element of the succeed login requests
        """
        r = self._get_request(Registration.URL_LOGIN)
        log.info("Connection OK")

        if (Registration.cookies_load(self.session, Registration.COOKIE_FILE) and
                not Registration.cookies_expired(self.session)):
            log.info("Use previous cookies from %r" % Registration.COOKIE_FILE)
        else:
            tree = lxml.html.fromstring(r.content)
            log.info("Logging in %r" % Registration.URL_LOGIN)
            r = self._login(tree)

        if r.status_code != 200:
            log.info("Current URL: %r" % r.url)
        else:
            log.info("[+] Login Success")

    @staticmethod
    def request(method, url, data=None, repeat=10):
        try:
            log.info("%s %r ..." % (method.__func__.__name__.upper(), url))
            n_try = 0

            while True:
                req = method(url, data=data, timeout=4)
                if req.status_code == 200:
                    return req
                if n_try >= repeat:
                    break
                n_try += 1
                log.warning("Trying %d times"%n_try)

            log.warning("status_code: %d" % req.status_code)
            log.error('Something wrong! Cannot connect!')

        except (requests.exceptions.ReadTimeout, requests.exceptions.ConnectionError):
            log.error("ConnectionError")

    @staticmethod
    def write_html(content):
        with open(Registration.DEBUG_OUTPUT_HTML, 'wb') as fd:
            fd.write(content)

    @staticmethod
    def get_value_from_name(tree, name):
        """get_value_from_name(tree, name) -> str

        Return value attribute from name attribute of an input tag.
        """
        assert isinstance(tree, lxml.html.HtmlElement)
        elements = tree.xpath("//input[@name='%(name)s']"%locals())
        return elements[0].value

    @staticmethod
    def cookies_save(session, filename):
        assert isinstance(session, requests.sessions.Session)
        try:
            with open(filename, 'wb') as fd:
                fd.truncate()
                pickle.dump(session.cookies._cookies, fd)
        except IOError:
            return False
        return True

    @staticmethod
    def cookies_load(session, filename):
        assert isinstance(session, requests.sessions.Session)
        try:
            cookies = None
            with open(filename, 'rb') as fd:
                cookies = pickle.load(fd)
            log.info("Loading cookie from %(filename)r ..."%locals())
            if cookies:
                jar = requests.cookies.RequestsCookieJar()
                jar._cookies = cookies
                session.cookies = jar
        except IOError:
            log.info("Cookie file: %(filename)r not found"%locals())
            return False
        return True

    @staticmethod
    def cookies_expired(session):
        assert isinstance(session, requests.sessions.Session)
        cookies = session.cookies._cookies
        s = cookies[Registration._COOKIE_KEY]['/'][Registration._COOKIE_JAR]
        return s.is_expired()

    HEADERS = {
        "User-Agent": "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0)",
        "Accept": "*/*",
        "Accept-Language": "en-US,en;q=0.5",
        "Connection": "keep-alive",
        }

    COOKIE_FILE  = '.rootme_cookie.txt'
    URL_LOGIN = 'https://www.root-me.org/spip.php?page=login&lang=en&ajax=1'

    DEBUG_OUTPUT_HTML = 'root-me-login.html'
    _COOKIE_KEY = '.www.root-me.org'
    _COOKIE_JAR = 'spip_session'


def main():
    print("""\
===============================
# Root-me login script by You #
==============================#""")
    login_name = input_login()
    passwd = input_password()
    register = Registration(login_name, passwd)
    register.login()


if __name__ == '__main__':
    main()
