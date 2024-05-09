import tkinter as tk
from tkinter import messagebox
import os
import bcrypt
import win32cred
import winreg

class Password_Manager:
    def __init__(self, default_password):
        self.app_name = "USB_Blocker"
        self.default_password = default_password
        self.init_password()

    def init_password(self):
        try:
            credential = win32cred.CredRead(self.app_name, win32cred.CRED_TYPE_GENERIC)
        except:
            self.change_password(self.default_password)

    def get_password(self):
        self.init_password()
        credential = win32cred.CredRead(self.app_name, win32cred.CRED_TYPE_GENERIC)
        return credential['CredentialBlob'].decode('utf-16')

    def correct_password(self, password):
        return bcrypt.checkpw(password.encode(), self.get_password().encode())

    def change_password(self, new_password):
        salt = bcrypt.gensalt()
        new_password = bcrypt.hashpw(new_password.encode(), salt).decode()
        credential = dict(Type=win32cred.CRED_TYPE_GENERIC, TargetName=self.app_name,
                          CredentialBlob=new_password,
                          Persist=win32cred.CRED_PERSIST_LOCAL_MACHINE)
        win32cred.CredWrite(credential, 0)


class PlaceholderEntry(tk.Entry):
    def __init__(self, master=None, placeholder=""):
        super().__init__(master)
        self.placeholder = placeholder
        self.insert(0, self.placeholder)
        self['fg'] = 'grey'
        self.bind("<FocusIn>", self._clear_placeholder)
        self.bind("<FocusOut>", self._add_placeholder)

    def _clear_placeholder(self, e):
        if self['fg'] == 'grey':
            self.delete(0, tk.END)
            self['fg'] = 'black'
            self.config(show='*')

    def _add_placeholder(self, e):
        if not self.get():
            self.insert(0, self.placeholder)
            self['fg'] = 'grey'
            self.config(show='')

    def reset(self):
        self.delete(0, tk.END)
        self.insert(0, self.placeholder)
        self['fg'] = 'grey'
        self.config(show='')

class USBControlApp:
    disabled_USB = []
    ori_using_USB = []

    def __init__(self):
        self.root = tk.Tk()
        self.root.geometry("280x80")
        self.root.title("USB Control Panel")
        self.root.protocol("WM_DELETE_WINDOW", self.On_Closing)
        # self.root.iconbitmap("USB_Blocker.ico")

        self.status_label = tk.Label(self.root, text="Enter password to enable USB")

        self.password_entry = PlaceholderEntry(self.root, "Password")
        self.password_entry.bind("<Return>", self.Login)

        self.password_old_entry = PlaceholderEntry(self.root, "Old Password")
        self.password_new1_entry = PlaceholderEntry(self.root, "New Password")
        self.password_new2_entry = PlaceholderEntry(self.root, "Confirm Password")
        self.password_new2_entry.bind("<Return>", self.Change_Password)

        self.enable_button = tk.Button(self.root, text='Enable', command=self.Login)
        self.disable_button = tk.Button(self.root, text='Disable', command=self.Disable_USB_Frame)
        self.change_password_button = tk.Button(self.root, text='Change Password', command=self.Change_Password_Frame)
        self.confirm_password_button = tk.Button(self.root, text='Enter', command=self.Change_Password)
        self.back_button = tk.Button(self.root, text='Back', command=self.Enable_USB_Frame)

        self.PW_Manager = Password_Manager("admin")

        self.Disable_USB_Frame()

    def Change_USB_Status(self, status):
        if status == "enable":
            value = 3
        else:
            value = 4

        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\USBSTOR", 0, winreg.KEY_SET_VALUE)
        winreg.SetValueEx(key, "Start", 0, winreg.REG_DWORD, value)
        winreg.CloseKey(key)

    def Enable_USB_Frame(self, event=None):
        self.USB_Mode = "enable"
        self.Change_USB_Status("enable")

        self.root.geometry("280x80")
        self.status_label.place(relx=0.5, rely=0.3, anchor='center')
        self.status_label.config(text="You can access USB now.")
        self.password_entry.place_forget()
        self.enable_button.place_forget()
        self.disable_button.place(relx=0.25, rely=0.7, anchor='center')
        self.change_password_button.place(relx=0.65, rely=0.7, anchor='center')
        self.password_old_entry.place_forget()
        self.password_new1_entry.place_forget()
        self.password_new2_entry.place_forget()
        self.confirm_password_button.place_forget()
        self.back_button.place_forget()

    def login_verify(self):
        if self.password_entry['fg'] == 'grey':
            messagebox.showerror("Error", "Please enter password")
            return False
        elif not self.PW_Manager.correct_password(self.password_entry.get()):
            messagebox.showerror("Error", "Wrong password")
            return False
        else:
            return True

    def Login(self, event=None):
        if self.login_verify():
            self.Enable_USB_Frame()
        else:
            self.password_entry.delete(0, tk.END)
            self.password_entry.focus_set()

    def Disable_USB_Frame(self, event=None):
        self.USB_Mode = "disable"
        self.Change_USB_Status("disable")

        self.status_label.place(relx=0.5, rely=0.3, anchor='center')
        self.status_label.config(text="Enter password to enable USB")
        self.password_entry.place(relx=0.4, rely=0.7, anchor='center')
        self.enable_button.place(relx=0.8, rely=0.7, anchor='center')
        self.change_password_button.place_forget()
        self.disable_button.place_forget()
        self.password_old_entry.place_forget()
        self.password_new1_entry.place_forget()
        self.password_new2_entry.place_forget()
        self.confirm_password_button.place_forget()
        self.back_button.place_forget()
        self.root.focus_set()
        self.password_entry.reset()
        self.password_entry.focus_set()

    def On_Closing(self, event=None):
        if self.USB_Mode == "enable" or self.login_verify():
            self.Change_USB_Status("enable")
            self.root.destroy()
        else:
            self.password_entry.delete(0, tk.END)
            self.password_entry.focus_set()

    def Change_Password_Frame(self, event=None):
        self.change_password_button.place_forget()
        self.disable_button.place_forget()
        self.status_label.place_forget()
        self.password_old_entry.place(relx=0.4, rely=0.2, anchor='center')
        self.password_new1_entry.place(relx=0.4, rely=0.5, anchor='center')
        self.password_new2_entry.place(relx=0.4, rely=0.8, anchor='center')
        self.confirm_password_button.place(relx=0.8, rely=0.8, anchor='center')
        self.back_button.place(relx=0.8, rely=0.2, anchor='center')
        self.root.geometry("280x110")

        self.password_old_entry.reset()
        self.password_new1_entry.reset()
        self.password_new2_entry.reset()
        self.root.focus_set()

    def change_password_confirm(self):
        old_password = ""
        new1_password = ""
        new2_password = ""

        if self.password_old_entry['fg'] != 'grey':
            old_password = self.password_old_entry.get()

        if self.password_new1_entry['fg'] != 'grey':
            new1_password = self.password_new1_entry.get()

        if self.password_new2_entry['fg'] != 'grey':
            new2_password = self.password_new2_entry.get()

        if not self.PW_Manager.correct_password(old_password):
            messagebox.showerror("Error", "Old password incorrect.")
            return False
        elif new1_password == "" or new2_password == "":
            messagebox.showerror("Error", "New password can't be empty.")
            return False
        elif new1_password != new2_password:
            messagebox.showerror("Error", "New password does not match.")
            return False
        else:
            self.PW_Manager.change_password(new1_password)
            messagebox.showinfo("Done", "Password changed successfully!")
            return True

    def Change_Password(self, event=None):
        if self.change_password_confirm():
            self.Enable_USB_Frame()
        else:
            self.Change_Password_Frame()

app = USBControlApp()
app.root.mainloop()
