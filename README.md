# PwP - Password Manager

A secure, user-friendly password manager for Windows.

## Features
- **Master password protection**: All your passwords are encrypted using a key derived from your master password.
- **Brute-force lockout**: Prevents repeated guessing of the master password.
- **Clipboard copy**: Easily copy passwords to your clipboard.
- **Password generation**: Generate strong, random passwords.
- **Simple GUI**: Easy-to-use interface built with Tkinter.
- **Configurable and local**: All data is stored locally; nothing is sent online.

## Installation
1. Clone or download this repository.
2. Install dependencies:
   ```sh
   pip install -r requirements.txt
   ```
3. (Optional) Build a standalone executable:
   ```sh
   pyinstaller --onefile --windowed --name=PwP password_manager.py
   ```
   The executable will appear in the `dist` folder as `PwP.exe`.

## Usage
- **First run**: You will be prompted to set a master password. This password will be required every time you open the app.
- **Add password**: Use the "Legg til passord" button to add a new password entry.
- **Copy password**: Select a password and click "Kopier passord" to copy it to the clipboard.
- **Show password**: Select a password and click "Vis passord" to display it.
- **Delete password/user**: Select and confirm deletion as prompted.
- **Help/About**: See the Help menu in the app for more info.

## Security Notes
- The master password is never stored in plaintext. Passwords are encrypted using Fernet with a key derived from your master password (PBKDF2).
- The app uses Argon2 for secure password hashing.
- After 5 failed master password attempts, the app locks for 30 seconds.
- All data is stored locally in encrypted form.

## Troubleshooting
- If you see a missing module error, make sure all dependencies are installed (`pip install -r requirements.txt`).
- If you forget your master password, **there is no recovery**. You must delete the config and key files to reset.

## Credits
Developed by Stian.

---

**Always remember your master password!**