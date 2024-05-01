import tkinter as tk
from tkinter import messagebox
import os
import time
import threading
import bcrypt
import win32cred

class Password_Manager:
    def __init__(self, default_password):
        self.app_name = "USB_Blocker"
        try:
            credential = win32cred.CredRead(self.app_name, win32cred.CRED_TYPE_GENERIC)
            self.__PASSWORD = credential['CredentialBlob'].decode('utf-16')
        except :
            self.change_password(default_password)

    def correct_password(self, password):
        return bcrypt.checkpw(password.encode(), self.__PASSWORD.encode())

    def change_password(self, new_password):
        salt = bcrypt.gensalt()
        self.__PASSWORD = bcrypt.hashpw(new_password.encode(), salt).decode()
        credential = dict(Type=win32cred.CRED_TYPE_GENERIC, TargetName=self.app_name, 
                          CredentialBlob=self.__PASSWORD,
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
        self.root.iconbitmap("USB_Blocker.ico")
        
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

        self.ori_using_USB = self.list_using_USB_devices()
        self.PW_Manager = Password_Manager("admin")

        self.Disable_Mode = True
        self.Disable_USB_Frame()

    def list_using_USB_devices(self):
        ps_command = 'pnputil /enum-devices /class "USB"'
        f = os.popen(ps_command)
        result = f.read()
        Device = []
        for line in result.splitlines():
            if b"\xe5\x9f\xb7\xe8\xa1\x8c\xe5\x80\x8b\xe9\xab\x94\xe8\xad\x98\xe5\x88\xa5\xe7\xa2\xbc" in line.encode() or b"Instance ID" in line.encode():
                device = line.split(":")[-1].strip()

            if b"\xe5\xb7\xb2\xe5\x95\x9f\xe5\x8b\x95" in line.encode() or b"Started" in line.encode() :  # using
                Device.append(device)

        return Device

    def Enable_USB(self):
        for device in self.disabled_USB:
            os.popen(f'pnputil /enable-device "{device}"')
            print("enable : " + device)

        self.disabled_USB = []

    def Enable_USB_Frame(self, event=None):
        self.Disable_Mode = False
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
            messagebox.showerror("Error", "Incorrect password")
            return False
        else:
            return True
        
    def Login(self, event=None):
        if self.login_verify():
            self.Enable_USB_Frame()
        else:
            self.password_entry.delete(0, tk.END)
            self.password_entry.focus_set()
        
    def Disable_USB(self):
        using_USB = self.list_using_USB_devices()
        for device in using_USB:
            if device not in self.ori_using_USB and device not in self.disabled_USB:
                f = os.popen(f'pnputil /disable-device "{device}"')
                print("disable : " + device)
                print(f.read())
                self.disabled_USB.append(device)

    def Disable_USB_Frame(self, event=None):
        self.Disable_Mode = True
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
        self.password_entry.reset()
        self.root.focus_set()
        
    def update_status(self):
        if self.Disable_Mode:  # disable
            self.Disable_USB()
        elif self.disabled_USB:  # enable
            self.Enable_USB()

    def On_Closing(self, event=None):
        if not self.Disable_Mode or self.login_verify():
            self.Enable_USB()
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
            messagebox.showerror("Error", "Incorrect old password")
            return False
        elif new1_password == "" or new2_password == "":
            messagebox.showerror("Error", "Empty new password")
            return False
        elif new1_password != new2_password:
            messagebox.showerror("Error", "Different new password")
            return False
        else:
            self.PW_Manager.change_password(new1_password)
            messagebox.showinfo("Done", "Password Changed!")
            return True

    def Change_Password(self, event=None):
        if self.change_password_confirm():
            self.Enable_USB_Frame()
        else:
            self.Change_Password_Frame()
    
app = USBControlApp()

def background_task():
    while True:
        time.sleep(0.5)
        app.update_status()

thread = threading.Thread(target=background_task)
thread.daemon = True
thread.start()

app.root.mainloop()