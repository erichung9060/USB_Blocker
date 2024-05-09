import win32cred
from tkinter import messagebox

def delete_windows_credential(target_name):
    try:
        win32cred.CredDelete(target_name, win32cred.CRED_TYPE_GENERIC)
        return True
    except Exception as e:
        print(f"Error:\n {e}")
        return False

deleted = delete_windows_credential("USB_Blocker")
if deleted:
    messagebox.showinfo("Done", "Sucessfully reset the password for USB Blocker")
else:
    messagebox.showinfo("Done", "You have already reset the password.")
