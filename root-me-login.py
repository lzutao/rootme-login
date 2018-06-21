#!/usr/bin/env python
from __future__ import print_function

from builtins import input, range, bytes

import getpass # Portable password input
import hashlib # for md5, sha256
import logging
import sys
import time

import requests
import lxml.html

from cookiebake import *

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s %(name)-12s %(levelname)-8s %(message)s',
)

log = logging.getLogger(__name__)

def input_login():
    login = input("Login: ")
    return login

def input_password():
    passwd = getpass.getpass('Password: ')
    return passwd

def calcule_hash_pass(login_info, password):
    """calcule_hash_pass(login_info, password) -> str
    Hash the password

    Params:
        login_info: array
        password: password from input_password()

    Return:
        The hashed password

    Example:
        calcule_hash_pass(login_info, 'aaaa') => {
            a557fff85d90f09c97c1db3c330ddd9ffa1d90e1f28743ad463c5a39e728553e;
            57e4684499603e19b2b6df03fec70f10622191d1fc9d913ef301512d15a9e5ab;
            41602b57e4934f52ccbb736301bcd25a;
            9ad21beadc9697d470d314f2a5349ccb
        }
    """
    sha256sum = hashlib.sha256
    md5sum = hashlib.md5
    alea_actuel = bytes(login_info['alea_actuel'] + password, 'utf-8')
    alea_futur = bytes(login_info['alea_futur'] + password, 'utf-8')

    res = '{%s;%s;%s;%s}' % (
        sha256sum(alea_actuel).hexdigest(),
        sha256sum(alea_futur).hexdigest(),
        md5sum(alea_actuel).hexdigest(),
        md5sum(alea_futur).hexdigest()
    )

    return res

def request(method, url, data=None, params=None, repeat=10):
    try:
        log.info("%s %r ..." % (method.__func__.__name__.upper(), url))
        for n_try in range(repeat):
            req = method(url, data=data, params=params, timeout=4)
            if req.status_code == requests.codes.ok:
                return req
            log.warning("Trying %d times"%(n_try + 1))

        log.error('Cannot connect! Code: %s' % (req.status_code))
    except (requests.exceptions.ReadTimeout, requests.exceptions.ConnectionError):
        log.error("ConnectionError")

def write_html(content, filename):
    with open(filename, 'wb') as fd:
        fd.write(content)

def get_value_from_name(tree, name):
    """get_value_from_name(tree, name) -> str

    Return value attribute from name attribute of an input tag.
    """
    assert isinstance(tree, lxml.html.HtmlElement)
    elements = tree.xpath("//input[@name='%(name)s']"%locals())
    return elements[0].value

class RootMe():
    """This class provide way to login in root-me.org"""
    def __init__(self, login_name, password):
        self.session = requests.Session()
        self.session.headers.update(RootMe.HEADERS)

        self.login_name = login_name
        self.password = password

        self.login_data  = {
            'var_ajax': 'form',
            'page': 'login',
            'url': '/?page=preferences&lang=en?page=preferences&lang=en',
            'lang': 'en',
            'formulaire_action': 'login',
            'formulaire_action_args': None,
            'var_login': self.login_name,
            'password': None,
        }

    def _get_request(self, url, params=None):
        r = request(self.session.get, url, params=params)
        return r

    def _login(self, tree):
        """_login(self, tree) -> requests.models.Response

        Send login_data and save cookies if succeed.
        Return a respone from that post request.
        """
        self.login_data['formulaire_action_args'] = get_value_from_name(tree, 'formulaire_action_args')

        login_info = self._actualise_auteur()
        self.login_data['password'] = calcule_hash_pass(login_info, self.password)

        r = request(self.session.post, RootMe.URL_LOGIN, data=self.login_data)

        if self.session.cookies._cookies:
            log.info('Login success ...')
            log.info("Saving cookies in %r ..." % RootMe.COOKIE_FILE)
            cookies_save(self.session, RootMe.COOKIE_FILE)
        else:
            write_html(r.content, RootMe.DEBUG_OUTPUT_HTML)
            log.error('Cannot login! Code=%d, URL=%r' % (r.status_code, r.url))
        return r

    def _actualise_auteur(self):
        payload = {
            'var_login': self.login_name,
            'var_compteur': int(time.time())
        }
        r = self._get_request(RootMe.AUTHOR_PAGE, params=payload)
        return r.json()

    def login(self):
        """login(self) -> lxml.html.HtmlElement

        Return html element of the succeed login requests
        """
        r = self._get_request(RootMe.URL_LOGIN)
        loaded = cookies_load(self.session, RootMe.COOKIE_FILE)

        if loaded and not cookies_expired(self.session, RootMe._COOKIE_DOMAIN, RootMe._COOKIE_JAR):
            log.info("Use previous cookies from %r" % RootMe.COOKIE_FILE)
        else:
            tree = lxml.html.fromstring(r.content)
            log.info("Try to log in %r" % RootMe.URL_LOGIN)
            r = self._login(tree)

        log.info("Current URL: %s" % r.url)
        r = self._get_request('https://www.root-me.org/?page=preferences&lang=en')
        if 'Se connecter' in r.text:
            log.info('[+] Login Fail')
        else:
            log.info("[+] Login Success")

    HEADERS = {
        "User-Agent": "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0)",
        "Accept": "*/*",
        "Accept-Language": "en-US,en;q=0.5",
        "Connection": "keep-alive",
    }

    COOKIE_FILE  = '.rootme_cookie.txt'
    URL_LOGIN = 'https://www.root-me.org/?page=login&url=%2F%3Fpage%3Dpreferences%26lang%3Den%3Fpage%3Dpreferences%26lang%3Den&lang=en'
    AUTHOR_PAGE = 'https://www.root-me.org/?page=informer_auteur'

    DEBUG_OUTPUT_HTML = 'root-me-login.html'
    _COOKIE_DOMAIN = '.www.root-me.org'
    _COOKIE_JAR = 'spip_session'


def main():
    print("""\
===============================
# Root-me login script by You #
==============================#""")
    login_name = input_login()
    passwd = input_password()
    rootme = RootMe(login_name, passwd)
    rootme.login()


if __name__ == '__main__':
    main()
