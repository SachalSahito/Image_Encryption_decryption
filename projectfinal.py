import os
import gzip
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
from tkinter import Tk, Label, Button, filedialog, simpledialog, messagebox
import hashlib
import re
import tkinter.ttk as ttk

class FileEncrypterDecrypter:
    def __init__(self, master):
        """
        Initialize the FileEncrypterDecrypter GUI application.

        Parameters:
        - master: The parent Tkinter window.
        """
        self.master = master
        master.title("File Encrypter Decrypter")

        master.geometry(("400x300"))
        # Create GUI elements
        self.label = Label(master, text="Select files to encrypt or decrypt:")
        self.label.grid(row=0, column=0, columnspan=2, padx=10, pady=5, sticky="w")

        self.encrypt_button = ttk.Button(master, text="Encrypt", command=self.encrypt_files, style='TButton')
        self.encrypt_button.grid(row=1, column=0, padx=10, pady=5, sticky="w")

        self.decrypt_button = ttk.Button(master, text="Decrypt", command=self.decrypt_files, style='TButton')
        self.decrypt_button.grid(row=1, column=1, padx=10, pady=5, sticky="e")

        self.label = Label(master, text="  Made by 21SW008, 21SW067, 21SW108", font=("Arial",8))
        self.label.grid(row=2, column=0, columnspan=2, padx=10, pady=5, sticky="w")


        self.progress_label = Label(master, text="")
        self.progress_label.grid(row=2, column=0, columnspan=2, padx=10, pady=5, sticky="w")

        self.progress_bar_encryption = ttk.Progressbar(master, mode='determinate')
        self.progress_bar_encryption.grid(row=3, column=0, columnspan=2, padx=10, pady=5, sticky="ew")
        self.progress_bar_encryption.grid_remove()

        self.progress_bar_compression = ttk.Progressbar(master, mode='determinate')
        self.progress_bar_compression.grid(row=4, column=0, columnspan=2, padx=10, pady=5, sticky="ew")
        self.progress_bar_compression.grid_remove()

    def derive_key(self, password, salt):
        """
        Derive a cryptographic key from the provided password and salt using PBKDF2.

        Parameters:
        - password: The password to derive the key from.
        - salt: A random salt used in key derivation.

        Returns:
        - key: The derived cryptographic key.
        """
        return PBKDF2(password, salt, dkLen=32, count=100000, prf=lambda p, s: hashlib.sha256(p + s).digest())

    def encrypt_files(self):
        """
        Encrypt selected files.
        """
        file_paths = filedialog.askopenfilenames()
        if not file_paths:
            messagebox.showerror("Error", "No files selected!")
            return

        password = self.get_strong_password("Enter password for encryption:")
        if not password:
            messagebox.showerror("Error", "Password cannot be empty!")
            return

        self.progress_label.config(text="Encrypting files...")
        self.progress_bar_encryption.grid()
        self.master.update()

        total_files = len(file_paths)
        for i, file_path in enumerate(file_paths, 1):
            self.progress_label.config(text=f"Encrypting file {i}/{total_files}")
            self.progress_bar_encryption['value'] = (i / total_files) * 100
            self.master.update()
            self.encrypt_file(file_path, password)

        self.progress_bar_encryption.grid_remove()
        self.progress_label.config(text="")
        messagebox.showinfo("Success", "Files encrypted successfully!")

    def decrypt_files(self):
        """
        Decrypt selected files.
        """
        file_paths = filedialog.askopenfilenames()
        if not file_paths:
            messagebox.showerror("Error", "No files selected!")
            return

        password = simpledialog.askstring("Password", "Enter password for decryption:", show='*')
        if not password:
            messagebox.showerror("Error", "Password cannot be empty!")
            return

        self.progress_label.config(text="Decrypting files...")
        self.progress_bar_encryption.grid()
        self.master.update()

        total_files = len(file_paths)
        for i, file_path in enumerate(file_paths, 1):
            self.progress_label.config(text=f"Decrypting file {i}/{total_files}")
            self.progress_bar_encryption['value'] = (i / total_files) * 100
            self.master.update()
            self.decrypt_file(file_path, password)

        self.progress_bar_encryption.grid_remove()
        self.progress_label.config(text="")
        messagebox.showinfo("Success", "Files decrypted successfully!")

    def get_strong_password(self, prompt):
        """
        Prompt the user for a strong password.

        Parameters:
        - prompt: The prompt message to display.

        Returns:
        - password: The entered password.
        """
        while True:
            password = simpledialog.askstring("Password", prompt, show='*')
            if not password:
                return None

            if not self.is_strong_password(password):
                messagebox.showerror("Error", "Password is weak. It should contain at least 8 characters, including uppercase, lowercase, digits, and special characters.")
            else:
                return password

    def is_strong_password(self, password):
        """
        Check if the provided password is strong.

        Parameters:
        - password: The password to check.

        Returns:
        - bool: True if the password is strong, False otherwise.
        """
        if len(password) < 8:
            return False

        if not re.search(r'[A-Z]', password):
            return False
        if not re.search(r'[a-z]', password):
            return False
        if not re.search(r'[0-9]', password):
            return False
        if not re.search(r'[^A-Za-z0-9]', password):
            return False

        return True

    def encrypt_file(self, file_path, password):
        """
        Encrypt a file using AES encryption with a random salt.

        Parameters:
        - file_path: The path to the file to encrypt.
        - password: The encryption password.
        """
        salt = get_random_bytes(16)
        key = self.derive_key(password.encode(), salt)

        cipher = AES.new(key, AES.MODE_EAX)

        with open(file_path, 'rb') as f:
            plaintext = f.read()

        self.progress_label.config(text="Compressing file...")
        self.progress_bar_compression.grid()
        self.master.update()

        compressed_plaintext = gzip.compress(plaintext)

        self.progress_bar_compression.grid_remove()
        self.progress_label.config(text="")

        ciphertext, tag = cipher.encrypt_and_digest(compressed_plaintext)

        encrypted_file_path = file_path + ".enc"
        with open(encrypted_file_path, 'wb') as f:
            [f.write(x) for x in (salt, cipher.nonce, tag, ciphertext)]

    def decrypt_file(self, file_path, password):
        """
        Decrypt an encrypted file and save the decrypted version.

        Parameters:
        - file_path: The path to the encrypted file.
        - password: The decryption password.
        """
        with open(file_path, 'rb') as f:
            salt, nonce, tag, ciphertext = [f.read(x) for x in (16, 16, 16, -1)]

        key = self.derive_key(password.encode(), salt)
        cipher = AES.new(key, AES.MODE_EAX, nonce)
        try:
            compressed_plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        except ValueError as e:
            messagebox.showerror("Error", "Failed to decrypt the file. Possible reasons: incorrect password or file corruption.")
            return

        plaintext = gzip.decompress(compressed_plaintext)

        decrypted_file_path = os.path.splitext(file_path)[0]  # Remove the ".enc" extension
        with open(decrypted_file_path, 'wb') as f_out:
            f_out.write(plaintext)

        messagebox.showinfo("Success", f"File decrypted and saved as {decrypted_file_path}")

root = Tk()
style = ttk.Style(root)
style.configure('TButton', foreground='blue', font=('Arial', 10))
app = FileEncrypterDecrypter(root)
root.mainloop()
