import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import base64
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend

class AESCipher:
    """
    Handles the AES-256-CBC encryption and decryption logic.
    """
    def __init__(self):
        self.backend = default_backend()
        self.block_size = 128 # AES block size is 128 bits
        self.key_size = 32    # 32 bytes = 256 bits

    def _derive_key(self, password: str, salt: bytes) -> bytes:
        """
        Derives a 32-byte key from the password using PBKDF2.
        """
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=self.key_size,
            salt=salt,
            iterations=100000,
            backend=self.backend
        )
        return kdf.derive(password.encode())

    def encrypt(self, plain_text: str, password: str) -> str:
        # 1. Generate a random salt and IV
        salt = os.urandom(16)
        iv = os.urandom(16)

        # 2. Derive key from password
        key = self._derive_key(password, salt)

        # 3. Pad the data (PKCS7) to fit block size
        padder = padding.PKCS7(self.block_size).padder()
        padded_data = padder.update(plain_text.encode()) + padder.finalize()

        # 4. Encrypt
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=self.backend)
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()

        # 5. Combine Salt + IV + Ciphertext
        # We need the Salt and IV to decrypt, so we pack them with the message
        combined = salt + iv + ciphertext

        # 6. Encode to Base64 for readable display
        return base64.b64encode(combined).decode('utf-8')

    def decrypt(self, encrypted_text_b64: str, password: str) -> str:
        try:
            # 1. Decode from Base64
            encrypted_data = base64.b64decode(encrypted_text_b64)

            # 2. Extract Salt (first 16 bytes), IV (next 16 bytes), and Content
            if len(encrypted_data) < 32:
                raise ValueError("Invalid data length")
            
            salt = encrypted_data[:16]
            iv = encrypted_data[16:32]
            ciphertext = encrypted_data[32:]

            # 3. Derive key using the extracted salt
            key = self._derive_key(password, salt)

            # 4. Decrypt
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=self.backend)
            decryptor = cipher.decryptor()
            padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

            # 5. Unpad
            unpadder = padding.PKCS7(self.block_size).unpadder()
            plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()

            return plaintext.decode('utf-8')
        
        except Exception as e:
            # Re-raise to be caught by UI
            raise ValueError("Decryption failed. Wrong password or corrupted data.")

class AESApp:
    def __init__(self, root):
        self.cipher = AESCipher()
        self.root = root
        self.root.title("Python AES Encryption Tool")
        self.root.geometry("600x550")
        self.root.resizable(False, False)

        # Apply a clean theme style
        style = ttk.Style()
        style.theme_use('clam')
        
        # --- Layout ---
        
        # Title Label
        title_label = ttk.Label(root, text="AES-256 Encryption (CBC Mode)", font=("Helvetica", 16, "bold"))
        title_label.pack(pady=10)

        # Input Frame
        input_frame = ttk.LabelFrame(root, text="Input Text", padding=10)
        input_frame.pack(fill="both", expand="yes", padx=10, pady=5)
        
        self.input_text = scrolledtext.ScrolledText(input_frame, height=5, font=("Consolas", 10))
        self.input_text.pack(fill="both", expand=True)

        # Password Frame
        pass_frame = ttk.Frame(root, padding=10)
        pass_frame.pack(fill="x", padx=10)
        
        ttk.Label(pass_frame, text="Secret Key (Password):", font=("Helvetica", 10, "bold")).pack(side="left")
        self.pass_entry = ttk.Entry(pass_frame, show="*", font=("Consolas", 10))
        self.pass_entry.pack(side="left", fill="x", expand=True, padx=(10, 0))
        
        # Buttons Frame
        btn_frame = ttk.Frame(root, padding=10)
        btn_frame.pack(fill="x")

        enc_btn = ttk.Button(btn_frame, text="Encrypt 🔒", command=self.do_encrypt)
        enc_btn.pack(side="left", fill="x", expand=True, padx=5)

        dec_btn = ttk.Button(btn_frame, text="Decrypt 🔓", command=self.do_decrypt)
        dec_btn.pack(side="left", fill="x", expand=True, padx=5)

        clear_btn = ttk.Button(btn_frame, text="Clear All", command=self.clear_all)
        clear_btn.pack(side="left", fill="x", expand=True, padx=5)

        # Output Frame
        output_frame = ttk.LabelFrame(root, text="Result (Base64)", padding=10)
        output_frame.pack(fill="both", expand="yes", padx=10, pady=5)
        
        self.output_text = scrolledtext.ScrolledText(output_frame, height=5, font=("Consolas", 10), state='disabled')
        self.output_text.pack(fill="both", expand=True)
        
        # Copy Button
        copy_btn = ttk.Button(root, text="Copy Result to Clipboard", command=self.copy_to_clipboard)
        copy_btn.pack(pady=10)

    def do_encrypt(self):
        text = self.input_text.get("1.0", tk.END).strip()
        password = self.pass_entry.get()

        if not text:
            messagebox.showwarning("Warning", "Please enter text to encrypt.")
            return
        if not password:
            messagebox.showwarning("Warning", "Please enter a password.")
            return

        try:
            encrypted = self.cipher.encrypt(text, password)
            self.display_output(encrypted)
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def do_decrypt(self):
        text = self.input_text.get("1.0", tk.END).strip()
        password = self.pass_entry.get()

        if not text:
            messagebox.showwarning("Warning", "Please enter the encrypted string.")
            return
        if not password:
            messagebox.showwarning("Warning", "Please enter the password.")
            return

        try:
            decrypted = self.cipher.decrypt(text, password)
            self.display_output(decrypted)
        except Exception as e:
            messagebox.showerror("Decryption Failed", "Invalid password or corrupted data.\nEnsure you copied the entire Base64 string.")

    def display_output(self, text):
        self.output_text.config(state='normal')
        self.output_text.delete("1.0", tk.END)
        self.output_text.insert(tk.END, text)
        self.output_text.config(state='disabled')

    def copy_to_clipboard(self):
        result = self.output_text.get("1.0", tk.END).strip()
        if result:
            self.root.clipboard_clear()
            self.root.clipboard_append(result)
            messagebox.showinfo("Copied", "Result copied to clipboard!")

    def clear_all(self):
        self.input_text.delete("1.0", tk.END)
        self.pass_entry.delete(0, tk.END)
        self.output_text.config(state='normal')
        self.output_text.delete("1.0", tk.END)
        self.output_text.config(state='disabled')

if __name__ == "__main__":
    root = tk.Tk()
    app = AESApp(root)
    root.mainloop()