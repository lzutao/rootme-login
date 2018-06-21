rootme-login
============

Python script to login into RootMe_ from the cli.
It is useful if you want to access challenges from your VPS.

.. _RootMe: https://www.root-me.org/?page=faq&lang=en

Status
------

Incompleted.

Dependencies
------------

.. code-block:: bash

   sudo apt-get install python-future python-requests python-lxml

Compability
-----------

This script support Python 2.7+ and Python 3.5+.

Usage
------------

.. code-block:: bash

   $ python root-me-login.py
   ===============================
   # Root-me login script by You #
   ==============================#
   Login: example@example.com
   Password:
   2018-06-21 06:00:10,029 root-me-login.py INFO     GET 'https://www.root-me.org/spip.php?page=login&lang=en&ajax=1' ...
   2018-06-21 06:00:11,209 root-me-login.py INFO     Connection OK
   2018-06-21 06:00:11,209 root-me-login.py INFO     Cookie file: '.rootme_cookie.txt' not found
   2018-06-21 06:00:11,210 root-me-login.py INFO     Logging in 'https://www.root-me.org/spip.php?page=login&lang=en&ajax=1'
   2018-06-21 06:00:11,210 root-me-login.py INFO     POST 'https://www.root-me.org/spip.php?page=login&lang=en&ajax=1' ...
   2018-06-21 06:00:12,022 root-me-login.py INFO     Login success ...
   2018-06-21 06:00:12,023 root-me-login.py INFO     Saving cookies in '.rootme_cookie.txt' ...
   2018-06-21 06:00:12,024 root-me-login.py INFO     [+] Login Success
   $ python root-me-login.py
   ===============================
   # Root-me login script by You #
   ==============================#
   Login:
   Password:
   2018-06-21 06:00:39,330 root-me-login.py INFO     GET 'https://www.root-me.org/spip.php?page=login&lang=en&ajax=1' ...
   2018-06-21 06:00:40,508 root-me-login.py INFO     Connection OK
   2018-06-21 06:00:40,508 root-me-login.py INFO     Loading cookie from '.rootme_cookie.txt' ...
   2018-06-21 06:00:40,508 root-me-login.py INFO     Use previous cookies from '.rootme_cookie.txt'
   2018-06-21 06:00:40,508 root-me-login.py INFO     [+] Login Success

And then connect to RootMe:

.. code-block:: bash

   $ ssh -p 2222 app-script-ch11@challenge01.root-me.org

