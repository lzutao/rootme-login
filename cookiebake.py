#!/usr/bin/env python
import pickle
import logging

import requests

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s %(name)-12s %(levelname)-8s %(message)s',
)

log = logging.getLogger(__name__)

def cookies_load(session, filename):
    assert isinstance(session, requests.sessions.Session)
    try:
        cookies = None
        with open(filename, 'rb') as fd:
            cookies = pickle.load(fd)
        log.info("Loading cookie from %(filename)r ..." % locals())
        if cookies:
            jar = requests.cookies.RequestsCookieJar()
            jar._cookies = cookies
            session.cookies = jar
    except IOError:
        log.info("Cookie file: %(filename)r not found" % locals())
        return False
    return True

def cookies_save(session, filename):
    assert isinstance(session, requests.sessions.Session)
    try:
        with open(filename, 'wb') as fd:
            fd.truncate()
            pickle.dump(session.cookies._cookies, fd)
    except IOError:
        return False
    return True


def cookies_expired(session, domain, key):
    assert isinstance(session, requests.sessions.Session)
    cookies = session.cookies._cookies
    if domain in cookies and key in cookies[domain]['/']:
        cookie_object = cookies[domain]['/'][key]
        return cookie_object.is_expired()
    return False
