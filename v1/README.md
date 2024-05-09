# Enter password to enable USB access
Block all devices that connect after the program has started. \\
The USB that was plugged in before the program started can still be used after the program has started.

* default password is "admin"
* requires administrator privilege
* disable task manager, that can force the program to close
* the password is encrypted using bcrypt, which may take a while processing after Enable button clicked.
* remove all USB devices before start this program
