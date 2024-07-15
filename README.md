INTEL UNNATI
PROBLEM STATEMENT--> "Protecting User Password Keys at rest(on the disk)".


File Encryptor/Decryptor README
Overview
This project is a Python-based application that provides encryption and decryption functionalities for files and directories using AES-256 and Argon2 for key derivation. The graphical user interface (GUI) is built with Tkinter, allowing users to easily encrypt and decrypt their sensitive data.

Features
AES-256 Encryption: Secure file encryption using the AES-256 algorithm in CFB mode.
Argon2 Key Derivation: Strong password hashing with Argon2 to derive encryption keys.
GUI: User-friendly interface for selecting files or directories and performing encryption/decryption operations.
File and Directory Support: Encrypts and decrypts individual files as well as entire directories.
Dependencies
The project relies on several Python libraries:

tkinter: For the graphical user interface.
pycryptodome: For cryptographic operations (AES).
argon2-cffi: For Argon2 password hashing.
shutil, os, time, json, queue, threading: Standard libraries for file operations and multithreading.
Installation
Install Python: Ensure you have Python 3.7+ installed on your machine.
Install Dependencies: Use pip to install the required libraries:
sh
Copy code
pip install pycryptodome argon2-cffi
Usage
Running the Application
To start the application, run the following command:

sh
Copy code
python your_script_name.py
Encrypting Files or Folders
Browse and Select: Use the "Browse File" or "Browse Folder" button to select the file or directory you want to encrypt.
Encrypt: Click the "Encrypt" button and enter a passphrase when prompted. The application will encrypt the selected file or directory, creating a new file with a .ept extension and a corresponding key file.
Decrypting Files or Folders
Browse and Select: Use the "Browse File" or "Browse Folder" button to select the encrypted file or directory (with a .ept extension).
Decrypt: Click the "Decrypt" button and enter the passphrase used for encryption. The application will decrypt the selected file or directory, restoring the original content.
Code Structure
FileEncryptor Class
This class handles the core encryption and decryption logic.

Initialization: Sets up the block size and password hasher.
Encryption:
encrypt_file: Encrypts individual files.
encrypt: Encrypts files or directories, derives keys, and manages key storage.
Decryption:
decrypt_file: Decrypts individual files.
decrypt: Decrypts files or directories, retrieves and decrypts keys, and restores original content.
GUIApp Class
This class creates and manages the graphical user interface using Tkinter.

Initialization: Sets up the main window and layout.
Event Handlers:
browse_file and browse_folder: Handle file and folder selection.
on_encrypt and on_decrypt: Handle encryption and decryption button clicks.
reset_entry: Resets the file path entry.
Multithreading:
encrypt_thread and decrypt_thread: Run encryption and decryption in separate threads.
show_loading: Displays a loading message while encryption/decryption is in progress.
Notes
Ensure you keep the passphrase secure, as it is required for decryption.
The encrypted files will have a .ept extension, and a corresponding key file will be generated with a .ept.key extension.
The application deletes the original files after encryption to maintain security.
Troubleshooting
File Not Found: Ensure the selected file or directory exists.
Incorrect Passphrase: Double-check the passphrase entered during decryption.
Dependencies: Make sure all required Python libraries are installed.
License
This project is licensed under the MIT License. See the LICENSE file for more details.

Acknowledgments
PyCryptodome
Argon2
This README provides an overview of the File Encryptor/Decryptor project, detailing its features, usage, and code structure. For any issues or contributions, please open an issue or pull request on the project's GitHub repository.

