import os
import json
import shutil
import time
import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog
from threading import Thread
import queue
from Crypto.Cipher import AES  # type: ignore
from Crypto.Random import get_random_bytes  # type: ignore
from argon2 import PasswordHasher  # type: ignore
from argon2.exceptions import VerifyMismatchError  # type: ignore

class FileEncryptor:
    def __init__(self):
        self.block_size = AES.block_size
        self.ph = PasswordHasher(time_cost=2, memory_cost=102400, parallelism=8)

    def get_user_passphrase(self, prompt="Enter your passphrase: "):
        root = tk.Tk()
        root.withdraw()
        passphrase = simpledialog.askstring("Passphrase", prompt, show='*')
        root.destroy()
        return passphrase.encode() if passphrase else None

    def generate_random_key(self):
        return get_random_bytes(32)  # 32 bytes for AES-256

    def derive_key(self, passphrase, salt):
        return self.ph.hash(passphrase.decode() + salt.hex()).encode()

    def encrypt_file(self, filepath, key):
        try:
            iv = get_random_bytes(self.block_size)
            cipher = AES.new(key, AES.MODE_CFB, iv)
            with open(filepath, 'rb') as f_in:
                content = f_in.read()
            return iv + cipher.encrypt(content)
        except FileNotFoundError:
            print(f"File not found: {filepath}")
            return None

    def decrypt_file(self, filepath, key):
        try:
            with open(filepath, 'rb') as f_in:
                ciphertext = f_in.read()
            iv = ciphertext[:self.block_size]
            cipher = AES.new(key, AES.MODE_CFB, iv)
            return cipher.decrypt(ciphertext[self.block_size:])
        except FileNotFoundError:
            print(f"File not found: {filepath}")
            return None

    def encrypt(self, filepath, passphrase):
        file_key = self.generate_random_key()
        salt = get_random_bytes(16)
        key_encryption_key = self.derive_key(passphrase, salt)

        if os.path.isfile(filepath):
            ciphertext = self.encrypt_file(filepath, file_key)
            if ciphertext is None:
                return False
            enc_filepath = f"{filepath}.ept"
            with open(enc_filepath, 'wb') as f_out:
                f_out.write(ciphertext)
            os.remove(filepath)
        else:
            new_dir = f"{filepath}.ept"
            os.makedirs(new_dir, exist_ok=True)
            for root, _, files in os.walk(filepath):
                for filename in files:
                    file_path = os.path.join(root, filename)
                    ciphertext = self.encrypt_file(file_path, file_key)
                    if ciphertext is None:
                        continue
                    rel_path = os.path.relpath(file_path, filepath)
                    enc_file_path = os.path.join(new_dir, f"{rel_path}.ept")
                    os.makedirs(os.path.dirname(enc_file_path), exist_ok=True)
                    with open(enc_file_path, 'wb') as f_out:
                        f_out.write(ciphertext)
                    os.remove(file_path)
            time.sleep(1)
            try:
                shutil.rmtree(filepath)
            except OSError as e:
                print(f"Error removing directory: {e}")

        iv = get_random_bytes(self.block_size)
        key_encryption_cipher = AES.new(key_encryption_key[:32], AES.MODE_CFB, iv)
        encrypted_file_key = iv + key_encryption_cipher.encrypt(file_key)

        key_info = {
            'salt': salt.hex(),
            'encrypted_file_key': encrypted_file_key.hex()
        }

        with open(f"{filepath}.ept.key", 'w') as f_out:
            json.dump(key_info, f_out)

        return True

    def decrypt(self, filepath, passphrase):
        key_file_path = f"{filepath[:-4]}.ept.key" if filepath.endswith('.ept') else f"{filepath}.ept.key"

        if not os.path.exists(key_file_path):
            print("Key file not found for decryption.")
            return False

        with open(key_file_path, 'r') as f_in:
            key_info = json.load(f_in)

        salt = bytes.fromhex(key_info['salt'])
        encrypted_file_key = bytes.fromhex(key_info['encrypted_file_key'])
        iv = encrypted_file_key[:self.block_size]
        encrypted_file_key = encrypted_file_key[self.block_size:]

        try:
            key_encryption_key = self.derive_key(passphrase, salt)
            key_encryption_cipher = AES.new(key_encryption_key[:32], AES.MODE_CFB, iv)
            file_key = key_encryption_cipher.decrypt(encrypted_file_key)
        except VerifyMismatchError:
            print("Incorrect passphrase or data integrity check failed.")
            return False

        if os.path.isfile(filepath) and filepath.endswith('.ept'):
            plaintext = self.decrypt_file(filepath, file_key)
            if plaintext is None:
                return False
            with open(filepath[:-4], 'wb') as f_out:
                f_out.write(plaintext)
            os.remove(filepath)
        else:
            new_dir = filepath.replace('.ept', '')
            os.makedirs(new_dir, exist_ok=True)
            for root, _, files in os.walk(filepath):
                for filename in files:
                    file_path = os.path.join(root, filename)
                    plaintext = self.decrypt_file(file_path, file_key)
                    if plaintext is None:
                        continue
                    rel_path = os.path.relpath(file_path, filepath)
                    dec_file_path = os.path.join(new_dir, rel_path[:-4])
                    os.makedirs(os.path.dirname(dec_file_path), exist_ok=True)
                    with open(dec_file_path, 'wb') as f_out:
                        f_out.write(plaintext)
                    os.remove(file_path)
            shutil.rmtree(filepath)

        os.remove(key_file_path)
        return True


class GUIApp:
    def __init__(self, root):
        self.encryptor = FileEncryptor()
        self.root = root
        self.root.title("File Encryptor/Decryptor")
        self.root.geometry("400x400")
        self.root.configure(bg='#FFFACD')

        self.frame = tk.Frame(root, padx=10, pady=10, bg='#FFFACD')
        self.frame.pack(padx=10, pady=10, expand=True)

        tk.Label(self.frame, text="Select File or Folder:", bg='#FFFACD', fg='black').grid(row=0, column=0, columnspan=4, sticky='w', pady=(10, 5))
        self.entry_filepath = tk.Entry(self.frame, width=40)
        self.entry_filepath.grid(row=1, column=0, columnspan=4, padx=5, pady=5)

        btn_style = {'font': ('Helvetica', 12), 'bg': 'blue', 'fg': 'white', 'activebackground': 'dark blue'}
        tk.Button(self.frame, text="Browse File", command=self.browse_file, **btn_style).grid(row=2, column=0, columnspan=2, padx=5, pady=5)
        tk.Button(self.frame, text="Browse Folder", command=self.browse_folder, **btn_style).grid(row=2, column=2, columnspan=2, padx=5, pady=5)

        tk.Button(self.frame, text="Encrypt", command=self.on_encrypt, font=('Helvetica', 12), bg='red', fg='white', activebackground='dark red').grid(row=3, column=0, columnspan=4, padx=5, pady=5)
        tk.Button(self.frame, text="Decrypt", command=self.on_decrypt, font=('Helvetica', 12), bg='orange', fg='white', activebackground='dark orange').grid(row=4, column=0, columnspan=4, padx=5, pady=5)
        tk.Button(self.frame, text="Reset", command=self.reset_entry, font=('Helvetica', 12), bg='grey', fg='white', activebackground='dark grey').grid(row=5, column=0, columnspan=4, padx=5, pady=5)

    def browse_file(self):
        filename = filedialog.askopenfilename()
        if filename:
            self.entry_filepath.delete(0, tk.END)
            self.entry_filepath.insert(0, filename)

    def browse_folder(self):
        foldername = filedialog.askdirectory()
        if foldername:
            self.entry_filepath.delete(0, tk.END)
            self.entry_filepath.insert(0, foldername)

    def reset_entry(self):
        self.entry_filepath.delete(0, tk.END)

    def on_encrypt(self):
        filepath = self.entry_filepath.get()
        if not filepath:
            messagebox.showerror("Error", "Please select a file or folder to encrypt.")
            return

        passphrase = self.encryptor.get_user_passphrase("Enter passphrase for encryption:")
        if passphrase:
            self.encrypt_thread(filepath, passphrase)

    def on_decrypt(self):
        filepath = self.entry_filepath.get()
        if not filepath:
            messagebox.showerror("Error", "Please select a file or folder to decrypt.")
            return

        passphrase = self.encryptor.get_user_passphrase("Enter passphrase for decryption:")
        if passphrase:
            self.decrypt_thread(filepath, passphrase)

    def show_loading(self, message, result_queue):
        loading_window = tk.Toplevel()
        loading_window.title("Please wait")
        tk.Label(loading_window, text=message).pack(padx=20, pady=20)

        def check_result():
            try:
                success = result_queue.get_nowait()
                loading_window.destroy()
                if success:
                    messagebox.showinfo("Success", f"{message} completed successfully.")
                else:
                    messagebox.showerror("Error", "Incorrect passphrase or an error occurred.")
                self.reset_entry()
            except queue.Empty:
                loading_window.after(100, check_result)

        loading_window.after(100, check_result)

    def encrypt_thread(self, filepath, passphrase):
        result_queue = queue.Queue()
        Thread(target=self.run_encryption, args=(filepath, passphrase, result_queue)).start()
        self.show_loading("Encrypting...", result_queue)

    def decrypt_thread(self, filepath, passphrase):
        result_queue = queue.Queue()
        Thread(target=self.run_decryption, args=(filepath, passphrase, result_queue)).start()
        self.show_loading("Decrypting...", result_queue)

    def run_encryption(self, filepath, passphrase, result_queue):
        result_queue.put(self.encryptor.encrypt(filepath, passphrase))

    def run_decryption(self, filepath, passphrase, result_queue):
        result_queue.put(self.encryptor.decrypt(filepath, passphrase))


if __name__ == "__main__":
    root = tk.Tk()
    app = GUIApp(root)
    root.mainloop()