import sqlite3
import tkinter as tk
from tkinter import messagebox, simpledialog
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from base64 import urlsafe_b64encode, urlsafe_b64decode
from argon2 import PasswordHasher  # Requires 'pip install argon2-cffi'
from argon2.exceptions import VerifyMismatchError
import os
import pyperclip
import random
import string
import configparser
import time

# --- Kryptering og nøkkelhåndtering ---
KEY_FILE = "encryption.key"
CONFIG_FILE = "config.ini"

def generate_and_encrypt_key(master_password):
    """Genererer en Fernet-nøkkel, krypterer den med en nøkkel avledet fra masterpassordet, og lagrer den med salt."""
    backend = default_backend()
    salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=390000,
        backend=backend
    )
    key_derived = urlsafe_b64encode(kdf.derive(master_password.encode()))
    fernet_key = Fernet.generate_key()
    f = Fernet(key_derived)
    encrypted_fernet_key = f.encrypt(fernet_key)
    with open(KEY_FILE, "wb") as key_file:
        key_file.write(salt + encrypted_fernet_key)
    return fernet_key

def load_and_decrypt_key(master_password):
    """Laster og dekrypterer Fernet-nøkkelen fra fil ved bruk av masterpassordet."""
    backend = default_backend()
    with open(KEY_FILE, "rb") as key_file:
        filedata = key_file.read()
    salt = filedata[:16]
    encrypted_fernet_key = filedata[16:]
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=390000,
        backend=backend
    )
    key_derived = urlsafe_b64encode(kdf.derive(master_password.encode()))
    f = Fernet(key_derived)
    try:
        fernet_key = f.decrypt(encrypted_fernet_key)
        return fernet_key
    except Exception:
        return None

def encrypt_password(password):
    """Krypterer et passord."""
    return cipher_suite.encrypt(password.encode()).decode()

def decrypt_password(encrypted_password):
    """Dekrypterer et passord."""
    return cipher_suite.decrypt(encrypted_password.encode()).decode()

def create_config_and_key_files():
    """Oppretter konfigurasjons- og nøkkelfil hvis de ikke finnes. Ber bruker om å velge et hovedpassord."""
    if not os.path.exists(CONFIG_FILE) or not os.path.exists(KEY_FILE):
        import tkinter.simpledialog
        import tkinter.messagebox
        root = tk.Tk()
        root.withdraw()
        while True:
            password1 = tkinter.simpledialog.askstring("Sett hovedpassord", "Velg et hovedpassord:", show="*")
            password2 = tkinter.simpledialog.askstring("Bekreft hovedpassord", "Bekreft hovedpassord:", show="*")
            if password1 is None or password2 is None:
                tkinter.messagebox.showerror("Avbrutt", "Du må angi et hovedpassord for å bruke programmet.")
                root.destroy()
                exit(1)
            if password1 != password2:
                tkinter.messagebox.showerror("Feil", "Passordene er ikke like. Prøv igjen.")
            elif len(password1) < 8:
                tkinter.messagebox.showerror("Feil", "Passordet må være minst 8 tegn.")
            else:
                break
        ph = PasswordHasher()
        hashed_password = ph.hash(password1)
        config = configparser.ConfigParser()
        config["security"] = {"password_hash": hashed_password}
        with open(CONFIG_FILE, "w") as config_file:
            config.write(config_file)
        # Generate and encrypt Fernet key
        generate_and_encrypt_key(password1)
        root.destroy()

# --- Les kryptert passord fra konfigurasjonsfil ---
def load_password_hash():
    config = configparser.ConfigParser()
    config.read(CONFIG_FILE)
    return config["security"]["password_hash"]

# --- Initialiser kryptering ---
def get_master_password_with_lockout():
    import tkinter.simpledialog
    import tkinter.messagebox
    failed_attempts = 0
    lockout_time = 30
    max_attempts = 5
    root = tk.Tk()
    root.withdraw()
    while True:
        password = tkinter.simpledialog.askstring("Masterpassord", "Oppgi hovedpassord:", show="*")
        if password is None:
            tkinter.messagebox.showerror("Avbrutt", "Du må angi hovedpassord for å bruke programmet.")
            root.destroy()
            exit(1)
        try:
            ph.verify(load_password_hash(), password)
            root.destroy()
            return password
        except VerifyMismatchError:
            failed_attempts += 1
            if failed_attempts >= max_attempts:
                tkinter.messagebox.showwarning("Låst", f"For mange feil. Prøver igjen om {lockout_time} sekunder.")
                root.update()
                time.sleep(lockout_time)
                failed_attempts = 0
            else:
                tkinter.messagebox.showerror("Feil", f"Ugyldig hovedpassord. {max_attempts-failed_attempts} forsøk igjen.")

create_config_and_key_files()
ph = PasswordHasher()
master_password = get_master_password_with_lockout()
ENCRYPTION_KEY = load_and_decrypt_key(master_password)
if ENCRYPTION_KEY is None:
    import tkinter.messagebox
    tkinter.messagebox.showerror("Feil", "Kunne ikke dekryptere nøkkelfil. Feil hovedpassord eller fil korrupt.")
    exit(1)
cipher_suite = Fernet(ENCRYPTION_KEY)
SECURITY_PASSWORD_HASH = load_password_hash()

# --- Databaseoppsett ---
DB_FILE = "passwords.db"

def setup_database():
    """Setter opp databasen hvis den ikke allerede finnes."""
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS passwords (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            website TEXT NOT NULL,
            username TEXT NOT NULL,
            password TEXT NOT NULL,
            user_id INTEGER NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    """)
    conn.commit()
    conn.close()

def register_user(username, password):
    """Registrerer en ny bruker i databasen."""
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    encrypted_password = encrypt_password(password)
    cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)", 
                   (username, encrypted_password))
    conn.commit()
    conn.close()

def authenticate_user(username, password):
    """Autentiserer en bruker."""
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT id, password FROM users WHERE username = ?", (username,))
    result = cursor.fetchone()
    conn.close()
    if result:
        user_id, stored_password = result
        if decrypt_password(stored_password) == password:
            return user_id
    return None

def user_exists():
    """Sjekker om det allerede finnes en bruker i databasen."""
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM users")
    count = cursor.fetchone()[0]
    conn.close()
    return count > 0

def wipe_program(security_password):
    """Sletter alt fra databasen hvis sikkerhetspassordet er korrekt."""
    try:
        ph.verify(SECURITY_PASSWORD_HASH, security_password)
    except VerifyMismatchError:
        return False
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("DELETE FROM users")
    cursor.execute("DELETE FROM passwords")
    conn.commit()
    conn.close()
    return True

# --- Passordhåndtering ---
def add_password_to_db(user_id, website, username, password):
    """Legger til et kryptert passord i databasen."""
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    encrypted_password = encrypt_password(password)
    cursor.execute("INSERT INTO passwords (website, username, password, user_id) VALUES (?, ?, ?, ?)", 
                   (website, username, encrypted_password, user_id))
    conn.commit()
    conn.close()

def get_passwords_from_db(user_id):
    """Henter alle passord for en bruker fra databasen."""
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT id, website, username, password FROM passwords WHERE user_id = ?", (user_id,))
    data = cursor.fetchall()
    conn.close()
    return data

def delete_password_from_db(password_id):
    """Sletter et passord fra databasen."""
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("DELETE FROM passwords WHERE id = ?", (password_id,))
    conn.commit()
    conn.close()

# --- Passordgenerering ---
def generate_password(length=16):
    """Genererer et sterkt passord."""
    characters = string.ascii_letters + string.digits + string.punctuation
    return ''.join(random.choice(characters) for _ in range(length))

# --- GUI ---
class PasswordManagerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Passord Manager")
        self.current_user_id = None
        self.setup_menu()
        self.setup_ui()

    def setup_menu(self):
        menubar = tk.Menu(self.root)
        helpmenu = tk.Menu(menubar, tearoff=0)
        helpmenu.add_command(label="About / Help", command=self.show_about)
        menubar.add_cascade(label="Help", menu=helpmenu)
        self.root.config(menu=menubar)

    def show_about(self):
        about_text = (
            "PwP - Password Manager\n\n"
            "A secure, user-friendly password manager.\n\n"
            "Features:\n"
            "- All passwords are encrypted with a master password.\n"
            "- Brute-force lockout for master password entry.\n"
            "- Clipboard copy for easy password use.\n\n"
            "Usage Tips:\n"
            "- Always remember your master password!\n"
            "- Use the 'Add Password' button to store new credentials.\n"
            "- Use the Help menu for more info.\n\n"
            "Developed by Stian."
        )
        messagebox.showinfo("About PwP", about_text)


    def setup_ui(self):
        """Setter opp brukergrensesnittet."""
        if not self.current_user_id:
            self.show_login_screen()
        else:
            self.show_password_manager()

    def show_login_screen(self):
        """Viser innloggingsskjermen."""
        self.clear_screen()
        tk.Label(self.root, text="Brukernavn:").grid(row=0, column=0, padx=5, pady=5)
        self.username_entry = tk.Entry(self.root)
        self.username_entry.grid(row=0, column=1, padx=5, pady=5)

        tk.Label(self.root, text="Passord:").grid(row=1, column=0, padx=5, pady=5)
        self.password_entry = tk.Entry(self.root, show="*")
        self.password_entry.grid(row=1, column=1, padx=5, pady=5)

        tk.Button(self.root, text="Logg inn", command=self.login).grid(row=2, column=0, padx=5, pady=5)
        tk.Button(self.root, text="Registrer", command=self.register).grid(row=2, column=1, padx=5, pady=5)
        tk.Button(self.root, text="Slett bruker", command=self.delete_user_prompt).grid(row=3, column=0, columnspan=2, padx=5, pady=5)

    def show_password_manager(self):
        """Viser hovedskjermen for passordhåndtering."""
        self.clear_screen()
        # print("Viser passordhåndtering for bruker:", self.current_user_id)  # Debug-melding

        self.password_list = tk.Listbox(self.root, height=15, width=50)
        self.password_list.grid(row=0, column=0, columnspan=3, padx=10, pady=10)
        self.load_passwords()

        tk.Button(self.root, text="Legg til passord", command=self.add_password).grid(row=1, column=0, padx=5, pady=5)
        tk.Button(self.root, text="Kopier passord", command=self.copy_password).grid(row=1, column=1, padx=5, pady=5)
        tk.Button(self.root, text="Slett passord", command=self.delete_password).grid(row=1, column=2, padx=5, pady=5)
        tk.Button(self.root, text="Vis passord", command=self.show_password).grid(row=2, column=0, padx=5, pady=5)
        tk.Button(self.root, text="Logg ut", command=self.logout).grid(row=2, column=1, padx=5, pady=5)
        tk.Button(self.root, text="Slett bruker", command=self.delete_user_prompt).grid(row=2, column=2, padx=5, pady=5)

    def clear_screen(self):
        """Fjerner alle widgets fra skjermen."""
        for widget in self.root.winfo_children():
            widget.destroy()

    def login(self):
        """Håndterer innlogging."""
        username = self.username_entry.get()
        password = self.password_entry.get()
        user_id = authenticate_user(username, password)
        if user_id:
            self.current_user_id = user_id
            # print("Innlogging vellykket, bruker-ID:", self.current_user_id)  # Debug-melding
            self.setup_ui()
        else:
            # print("Innlogging feilet for bruker:", username)  # Debug-melding
            messagebox.showerror("Feil", "Ugyldig brukernavn eller passord.")

    def register(self):
        """Håndterer registrering."""
        if user_exists():
            messagebox.showerror("Feil", "En bruker er allerede registrert.")
            return

        security_password = simpledialog.askstring("Sikkerhet", "Oppgi sikkerhetspassord:")
        if wipe_program(security_password):
            username = simpledialog.askstring("Registrer", "Velg brukernavn:")
            password = simpledialog.askstring("Registrer", "Velg passord (minst 8 tegn):", show="*")
            if len(password) >= 8:
                register_user(username, password)
                messagebox.showinfo("Suksess", "Bruker opprettet!")
            else:
                messagebox.showerror("Feil", "Passord må være minst 8 tegn.")
        else:
            messagebox.showerror("Feil", "Ugyldig sikkerhetspassord.")

    def logout(self):
        """Logger ut brukeren."""
        self.current_user_id = None
        self.setup_ui()

    def load_passwords(self):
        """Laster passordene inn i listen."""
        self.password_list.delete(0, tk.END)
        passwords = get_passwords_from_db(self.current_user_id)
        # print("Laster passord for bruker:", self.current_user_id)  # Debug-melding
        for password in passwords:
            # print("Legger til passord i listen:", password)  # Debug-melding
            self.password_list.insert(tk.END, f"{password[1]} ({password[2]})")

    def add_password(self):
        """Legger til et nytt passord."""
        website = simpledialog.askstring("Legg til passord", "Nettsted:")
        username = simpledialog.askstring("Legg til passord", "Brukernavn:")
        use_generated_password = messagebox.askyesno("Generer passord", "Vil du generere et sterkt passord?")
        if use_generated_password:
            length = simpledialog.askinteger("Lengde", "Oppgi passordlengde (opptil 100 tegn):", minvalue=1, maxvalue=100)
            password = generate_password(length)
            messagebox.showinfo("Generert passord", f"Ditt genererte passord er: {password}")
        else:
            password = simpledialog.askstring("Legg til passord", "Passord:", show="*")
        if website and username and password:
            add_password_to_db(self.current_user_id, website, username, password)
            self.load_passwords()
            messagebox.showinfo("Suksess", "Passord lagret!")

    def copy_password(self):
        """Kopierer valgt passord."""
        selected = self.password_list.curselection()
        if selected:
            password_data = get_passwords_from_db(self.current_user_id)[selected[0]]
            decrypted_password = decrypt_password(password_data[3])
            pyperclip.copy(decrypted_password)
            messagebox.showinfo("Kopiert", "Passord kopiert til utklippstavlen.")
        else:
            messagebox.showwarning("Ingen valgt", "Velg et passord for å kopiere.")

    def delete_password(self):
        """Sletter det valgte passordet."""
        selected = self.password_list.curselection()
        if selected:
            confirm_delete = simpledialog.askstring("Bekreft sletting", "Skriv 'DELETE' for å bekrefte sletting:")
            if confirm_delete == "DELETE":
                password_data = get_passwords_from_db(self.current_user_id)[selected[0]]
                delete_password_from_db(password_data[0])
                self.load_passwords()
                messagebox.showinfo("Suksess", "Passord slettet!")
            else:
                messagebox.showwarning("Avbrutt", "Sletting avbrutt.")
        else:
            messagebox.showwarning("Ingen valgt", "Velg et passord for å slette.")

    def show_password(self):
        """Viser det valgte passordet."""
        selected = self.password_list.curselection()
        if selected:
            password_data = get_passwords_from_db(self.current_user_id)[selected[0]]
            decrypted_password = decrypt_password(password_data[3])
            messagebox.showinfo("Passord", f"Passord: {decrypted_password}")
        else:
            messagebox.showwarning("Ingen valgt", "Velg et passord for å vise.")

    def delete_user_prompt(self):
        """Ber om bekreftelse for å slette brukeren."""
        security_password = simpledialog.askstring("Sikkerhet", "Oppgi sikkerhetspassord:")
        try:
            ph.verify(SECURITY_PASSWORD_HASH, security_password)
        except VerifyMismatchError:
            messagebox.showerror("Feil", "Ugyldig sikkerhetspassord.")
            return
        response = messagebox.askyesno("Bekreft sletting", "Er du sikker på at du vil slette alle data?")
        if response:
            confirm_delete = simpledialog.askstring("Bekreft sletting", "Skriv 'DELETE' for å bekrefte sletting:")
            if confirm_delete == "DELETE":
                self.wipe_all_data()
            else:
                messagebox.showwarning("Avbrutt", "Sletting avbrutt.")

    def wipe_all_data(self):
        """Sletter alle data fra databasen."""
        security_password = simpledialog.askstring("Sikkerhet", "Oppgi sikkerhetspassord:")
        if wipe_program(security_password):
            self.logout()

# --- Hovedprogram ---
if __name__ == "__main__":
    setup_database()
    root = tk.Tk()
    app = PasswordManagerApp(root)
    root.mainloop()