# Enter password to enable USB access
block all devices that are connected after program started.

* default password is "admin"
* requires administrator privilege
* disable task manager, that can force the program to close
* the password is encrypted using bcrypt, which may take a while processing after Enable button clicked.
* remove all USB devices before start this program