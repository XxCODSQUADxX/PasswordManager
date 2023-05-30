import sqlite3
from os import urandom
from tkinter import *
from tkinter import messagebox
import random
import string
import bcrypt
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from base64 import urlsafe_b64encode
from tkinter import ttk

import platform
import subprocess
import ctypes


class PasswordManager:
    def __init__(self):
        self.conn = sqlite3.connect('accounts.db')
        self.cursor = self.conn.cursor()
        self.create_table()
        self.key = None
        self.fernet = None
        self.master_password= None


    def create_table(self):
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS accounts(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                site TEXT NOT NULL,
                site_username TEXT NOT NULL,
                site_password TEXT NOT NULL,
                salt BLOB NOT NULL,
                FOREIGN KEY (user_id) REFERENCES user(id)
            );
        ''')
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS user(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL,
                master_password TEXT NOT NULL,
                salt BLOB NOT NULL
            );
        ''')
        self.conn.commit()

    def main_menu(self):
        def open_add_account():
            self.window.destroy()
            self.add_account_ui()

        def open_retrieve_accounts():
            self.window.destroy()
            self.retrieve_accounts_ui()

        def open_search_accounts():
            self.window.destroy()
            self.search_accounts_ui()

        self.window = Tk()
        self.window.title("Main Menu")

        add_account_button = Button(self.window, text="Add Account", command=open_add_account)
        add_account_button.pack()

        retrieve_accounts_button = Button(self.window, text="Retrieve Accounts", command=open_retrieve_accounts)
        retrieve_accounts_button.pack()

        search_accounts_button = Button(self.window, text="Search Accounts", command=open_search_accounts)
        search_accounts_button.pack()

        self.window.mainloop()
    def login(self):
        window = Tk()
        window.title("Login")



        def submit():
            username = username_entry.get()
            master_password = master_password_entry.get()

            self.cursor.execute('SELECT id, master_password, salt FROM user WHERE username = ?', (username,))
            user = self.cursor.fetchone()

            if user is not None:
                user_id, hashed_password, salt = user
                if bcrypt.checkpw(master_password.encode(), hashed_password):
                    messagebox.showinfo("Success", "Login successful!")
                    window.destroy()
                    self.user_id = user_id  # Store the user_id in self.user_id
                    self.master_password=master_password
                    self.main_menu()
                else:
                    messagebox.showerror("Error", "Wrong username or password!")
            else:
                messagebox.showerror("Error", "Wrong username or password!")

        def create_user():
            username = username_entry.get()
            master_password = master_password_entry.get()

            salt = bcrypt.gensalt()
            hashed_password = bcrypt.hashpw(master_password.encode(), salt)

            self.cursor.execute('''
                                INSERT INTO user(username, master_password, salt) VALUES(?,?,?);
                            ''', (username, hashed_password, salt,))
            self.conn.commit()
            window.destroy()
            self.login()

        username_label = Label(window, text="Username")
        username_label.pack()
        username_entry = Entry(window)
        username_entry.pack()

        master_password_label = Label(window, text="Master Password")
        master_password_label.pack()
        master_password_entry = Entry(window, show="*")
        master_password_entry.pack()

        submit_button = Button(window, text="Submit", command=submit)
        submit_button.pack()

        new_user = Button(window,text="New Account",command=create_user)
        new_user.pack()

        window.mainloop()

    def setup_user(self):
        self.cursor.execute('SELECT * FROM user')
        user = self.cursor.fetchone()

        if user is None:
            window = Tk()
            window.title("Setup User")

            def submit():
                username = username_entry.get()
                master_password = master_password_entry.get()

                salt = bcrypt.gensalt()
                hashed_password = bcrypt.hashpw(master_password.encode(), salt)

                self.cursor.execute('''
                    INSERT INTO user(username, master_password, salt) VALUES(?,?,?);
                ''', (username, hashed_password, salt,))
                self.conn.commit()
                window.destroy()
                self.login()

            username_label = Label(window, text="Username")
            username_label.pack()
            username_entry = Entry(window)
            username_entry.pack()

            master_password_label = Label(window, text="Master Password")
            master_password_label.pack()
            master_password_entry = Entry(window, show="*")
            master_password_entry.pack()

            submit_button = Button(window, text="Submit", command=submit)
            submit_button.pack()

            window.mainloop()

        else:
            self.login()

    def add_account(self, site, site_username, site_password):
        salt = urandom(16)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )

        key = urlsafe_b64encode(kdf.derive(self.master_password.encode()))
        f = Fernet(key)
        encrypted_password = f.encrypt(site_password.encode())

        self.cursor.execute('''
                INSERT INTO accounts(user_id, site, site_username, site_password, salt) VALUES(?,?,?,?,?);
            ''', (self.user_id, site, site_username, encrypted_password, salt,))
        self.conn.commit()

    def delete_account_record(self, account_id):
        self.cursor.execute('DELETE FROM accounts WHERE id = ?;', (account_id,))
        self.conn.commit()

    def retrieve_accounts(self):
        self.cursor.execute('SELECT id, site, site_username, site_password, salt FROM accounts WHERE user_id = ?;', (self.user_id,))
        rows = self.cursor.fetchall()

        decrypted_accounts = []
        for row in rows:
            account_id, site, site_username, encrypted_site_password, salt = row
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100000,
            )
            key = urlsafe_b64encode(kdf.derive(self.master_password.encode()))
            f = Fernet(key)
            decrypted_site_password = f.decrypt(encrypted_site_password).decode()
            decrypted_accounts.append((account_id, site, site_username, decrypted_site_password))

        return decrypted_accounts

    def search_accounts(self, site):
        self.cursor.execute(
            'SELECT id, site, site_username, site_password, salt FROM accounts WHERE user_id = ? AND site LIKE ?;',
            (self.user_id, '%' + site + '%',))
        rows = self.cursor.fetchall()

        decrypted_accounts = []
        for row in rows:
            account_id, site, site_username, encrypted_site_password, salt = row
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100000,
            )
            key = urlsafe_b64encode(kdf.derive(self.master_password.encode()))
            f = Fernet(key)
            decrypted_site_password = f.decrypt(encrypted_site_password).decode()
            decrypted_accounts.append((account_id, site, site_username, decrypted_site_password))

        return decrypted_accounts

    def add_account_ui(self):
        def generate_password(length=16):
            chars = string.ascii_letters + string.digits + string.punctuation
            return ''.join(random.choice(chars) for _ in range(length))

        def submit():
            site = self.site_entry.get()
            site_username = self.site_username_entry.get()
            if self.var.get():
                site_password = generate_password()
            else:
                site_password = self.site_password_entry.get()
            self.add_account(site, site_username, site_password)
            self.site_entry.delete(0, END)
            self.site_username_entry.delete(0, END)
            self.site_password_entry.delete(0, END)
            messagebox.showinfo("Success",
                                f"Account added successfully! Site: {site}, Site Username: {site_username}, Site Password: {site_password}")

        def back():
            self.window.destroy()
            self.main_menu()

        self.window = Tk()
        self.window.title("Add Account")

        self.site_label = Label(self.window, text="Site")
        self.site_label.pack()
        self.site_entry = Entry(self.window)
        self.site_entry.pack()

        self.site_username_label = Label(self.window, text="Site Username")
        self.site_username_label.pack()
        self.site_username_entry = Entry(self.window)
        self.site_username_entry.pack()

        self.site_password_label = Label(self.window, text="Site Password")
        self.site_password_label.pack()
        self.site_password_entry = Entry(self.window)
        self.site_password_entry.pack()

        self.var = IntVar()
        generate_password_checkbutton = Checkbutton(self.window, text="Generate password", variable=self.var)
        generate_password_checkbutton.pack()

        submit_button = Button(self.window, text="Submit", command=submit)
        submit_button.pack()

        back_button = Button(self.window, text="Back", command=back)
        back_button.pack()

        self.window.mainloop()

    def edit_account_ui(self):
        def generate_password(length=16):
            chars = string.ascii_letters + string.digits + string.punctuation
            return ''.join(random.choice(chars) for _ in range(length))
        def submit():
            site = site_entry.get()
            site_username = site_username_entry.get()
            site_password = site_password_entry.get()


            self.update_account(*self.selected_account, site, site_username, site_password)
            self.edit_window.destroy()
            messagebox.showinfo("Success",
                                f"Account added successfully! Site: {site}, Site Username: {site_username}, Site Password: {site_password}")
        def rsubmit():
            site = site_entry.get()
            site_username = site_username_entry.get()

            site_password = generate_password()

            self.update_account(*self.selected_account, site, site_username, site_password)
            self.edit_window.destroy()
            messagebox.showinfo("Success",
                                f"Account added successfully! Site: {site}, Site Username: {site_username}, Site Password: {site_password}")

        self.edit_window = Tk()
        self.edit_window.title("Edit Account")

        site_label = Label(self.edit_window, text="Site")
        site_label.pack()
        site_entry = Entry(self.edit_window)
        site_entry.insert(0, self.selected_account[1])
        site_entry.pack()

        site_username_label = Label(self.edit_window, text="Site Username")
        site_username_label.pack()
        site_username_entry = Entry(self.edit_window)
        site_username_entry.insert(0, self.selected_account[2])
        site_username_entry.pack()

        site_password_label = Label(self.edit_window, text="Site Password")
        site_password_label.pack()
        site_password_entry = Entry(self.edit_window)
        site_password_entry.insert(0, self.selected_account[3])
        site_password_entry.pack()


        self.generate_radiobttn = Button(self.edit_window, text = 'Generate Password', command=rsubmit)
        self.generate_radiobttn.pack()


        submit_button = Button(self.edit_window, text="Submit", command=submit)
        submit_button.pack()

        self.edit_window.mainloop()

    def update_account(self, pk,old_site, old_site_username, _, new_site, new_site_username, new_site_password):
        conn = sqlite3.connect('accounts.db')
        cursor = conn.cursor()

        salt = urandom(16)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = urlsafe_b64encode(kdf.derive(self.master_password.encode()))
        f = Fernet(key)
        encrypted_password = f.encrypt(new_site_password.encode())
        cursor.execute('''
            UPDATE accounts
            SET site = ?, site_username = ?, site_password = ?, salt = ?
            WHERE id = ?;
        ''', (new_site, new_site_username, encrypted_password, salt, pk))

        conn.commit()
        conn.close()

    def retrieve_accounts_ui(self):
        def select_item(event):
            cur_selection = self.tree_view.focus()
            selected = self.tree_view.item(cur_selection)
            self.selected_account = selected['values']

        def delete_account():
            if self.selected_account:
                account_id, _, _, _ = self.selected_account  # Assuming PK is the third item in the tuple
                self.delete_account_record(account_id)
                self.tree_view.delete(self.tree_view.focus())
                self.selected_account = None

        def edit_account():
            if self.selected_account:
                # This should open a new window to edit the account
                self.edit_account_ui()

        def copy_password(event):
            cur_selection = self.tree_view.focus()
            selected = self.tree_view.item(cur_selection)
            password = selected['values'][3]  # Assuming the password is the fourth item in the tuple
            self.copy_to_clipboard(password)

        def back():
            self.window.destroy()
            self.main_menu()

        self.window = Tk()
        self.window.title("Retrieve Accounts")

        self.tree_view = ttk.Treeview(self.window, columns=('ID', 'Site', 'Site Username', 'Site Password'))
        self.tree_view.heading('#0', text='Item No')
        self.tree_view.heading('#1', text='ID')
        self.tree_view.heading('#2', text='Site')
        self.tree_view.heading('#3', text='Site Username')
        self.tree_view.heading('#4', text='Site Password')
        self.tree_view.bind('<<TreeviewSelect>>', select_item)
        self.tree_view.pack()

        accounts = self.retrieve_accounts()
        for idx, account in enumerate(accounts, start=1):
            id, site, site_username, site_password = account
            self.tree_view.insert('', 'end', text=str(idx), values=(id, site, site_username, site_password))

        self.tree_view.pack()

        delete_account_button = Button(self.window, text="Delete Account", command=delete_account)
        delete_account_button.pack()

        edit_account_button = Button(self.window, text="Edit Account", command=edit_account)
        edit_account_button.pack()

        edit_account_button = Button(self.window, text="Back", command=back)
        edit_account_button.pack()

        # Bind double-click event to copy password
        self.tree_view.bind('<Double-Button-1>', copy_password)

        self.window.mainloop()

    def copy_to_clipboard(self, text):
        system = platform.system()
        if system == 'Linux':
            subprocess.run(['xclip', '-selection', 'clipboard'], input=text.encode())
        elif system == 'Darwin':
            subprocess.run(['pbcopy'], input=text.encode())
        elif system == 'Windows':
            ctypes.windll.user32.OpenClipboard(0)
            ctypes.windll.user32.EmptyClipboard()
            ctypes.windll.user32.SetClipboardData(1, ctypes.c_wchar_p(text))
            ctypes.windll.user32.CloseClipboard()
        # Display a message box to notify the user
        messagebox.showinfo("Copy to Clipboard", "Item has been copied to the clipboard.")

    def search_accounts_ui(self):
        def submit():
            site = self.site_entry.get()
            accounts = self.search_accounts(site)

            # Clear the treeview
            self.tree_view.delete(*self.tree_view.get_children())

            if accounts:
                for idx, account in enumerate(accounts, start=1):
                    id,site, site_username, site_password = account
                    self.tree_view.insert('', 'end', text=str(idx), values=(id,site, site_username, site_password))
            else:
                messagebox.showinfo("Error", "No accounts found for the specified site.")

        def select_item(event):
            cur_selection = self.tree_view.focus()
            selected = self.tree_view.item(cur_selection)
            self.selected_account = selected['values']

        def delete_account():
            if self.selected_account:
                account_id, _, _,_ = self.selected_account  # Assuming pk is the third item in the tuple
                print(self.selected_account)
                self.delete_account_record(account_id)
                self.tree_view.delete(self.tree_view.focus())
                self.selected_account = None

        def edit_account():
            if self.selected_account:
                # This should open a new window to edit the account
                self.edit_account_ui()

        def back():
            self.window.destroy()
            self.main_menu()

        self.window = Tk()
        self.window.title("Search Accounts")

        self.site_label = Label(self.window, text="Site")
        self.site_label.pack()
        self.site_entry = Entry(self.window)
        self.site_entry.pack()

        self.tree_view = ttk.Treeview(self.window, columns=('ID','Site', 'Site Username', 'Site Password'))
        self.tree_view.heading('#0', text='Item No')
        self.tree_view.heading('#1', text='ID')
        self.tree_view.heading('#2', text='Site')
        self.tree_view.heading('#3', text='Site Username')
        self.tree_view.heading('#4', text='Site Password')
        self.tree_view.bind('<<TreeviewSelect>>', select_item)
        self.tree_view.pack()

        submit_button = Button(self.window, text="Submit", command=submit)
        submit_button.pack()

        delete_account_button = Button(self.window, text="Delete Account", command=delete_account)
        delete_account_button.pack()

        edit_account_button = Button(self.window, text="Edit Account", command=edit_account)
        edit_account_button.pack()

        back_button = Button(self.window, text="Back", command=back)
        back_button.pack()

        self.window.mainloop()

    # The rest of your code would then continue with the UI methods. Note that each of the UI methods should also be class methods now and will need to reference the instance methods like self.add_account(), self.delete_account(), etc.
if __name__ == "__main__":
    # Instantiate the PasswordManager
    password_manager = PasswordManager()

    # Setup user
    password_manager.login()

    # Open the main menu
    # password_manager.main_menu()
