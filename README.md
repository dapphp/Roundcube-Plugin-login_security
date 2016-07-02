Roundcube Plugin login_security
====================================
Additional login security for Roundcube.  This plugin helps secure your
users by adding enhanced brute-force protection, CAPTCHA after a number of
failed logins, as well as 2-factor authentication using TOTP.

Brute force prevention will block an IP address from attempting to log in to
any mailbox after so many failed attempts in a defined period of time.  For 
example you can choose to block an IP for 15 minutes after 20 failed logins in
a 5 minute period, or a 5 minute lockout after 10 failed attempts in 15 minutes.

You also have the option of requiring a CAPTCHA after a specific number of
failed logins.

Finally, users can add 2-factor authentication to their mailboxes by setting up
a time-based one time password for their account.  From the Settings menu, the
user can create and view an OTP key for their account.  The OTP is compatible
with Google Authenticator and FreeOTP Authenticator.  Apps can be configured
by scanning a barcode, or manually.

In addition to the authenticator app, this plugin allows for recovery codes to
be created as an alternate to using the authenticator.  Each recovery code can
only be used one time, unless they are re-entered in settings after being used. 

Install
-------
Using composer:

* Edit `composer.json` in the root directory where Roundcube is installed
* In the `require` section, add `"sonic/login_security": "~1.0"`
* This will install the required packages as well as create the required database tables
* See the [Roundcube plugins][rcplugins] site for more information.

Configuration
-------------

TODO - Describe configuration options

Usage
-----

TODO - Describe OTP setup and recovery codes

Screenshots
-----------
TODO - Add screenshots

Copyright
---------
Copyright (c) 2016 Sonic.net, Inc.  This software is released under the
[BSD-3 license][bsd-3].  See the included `LICENSE` file for details.
 
[bsd-3]: https://opensource.org/licenses/BSD-3-Clause
[rcplugins]: https://plugins.roundcube.net/
