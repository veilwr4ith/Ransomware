# Ransomware Implementation

## Introduction

This repository contains an implementation of ransomware in Python. This ransomware script is created for educational and research purposes only and should not be used for illegal activities. The author of this code will not be held responsible for any misuse or damage caused by this script.

## Features

- Encrypt files using strong encryption algorithms.
- Manage encryption keys derived from user-provided passwords.
- Timer functionality to schedule the deletion of decryption keys after a specified time.
- Command-line interface (CLI) for encrypting and decrypting files or folders.

## Usage

### Prerequisites

- Python 3.x
- `cryptography` library (install via `pip install cryptography`)

### Usage Instructions

1. **Clone the repository to your local machine:**

   ```bash
   git clone https://github.com/your-username/ransomware-implementation.git
   ```

2. **Navigate to the project directory:**

   ```bash
   cd ransomware-implementation
   ```

3. **Run the script with the desired options:**

   - To encrypt a file or folder:
   
     ```bash
     python ransomware.py -s 32 -e /path/to/file_or_folder -t 60
     ```
   
   - To decrypt a file or folder:
   
     ```bash
     python ransomware.py -d /path/to/file_or_folder 
     ```

   **Note:** You will be prompted to enter a password for encryption or decryption.

## Disclaimer

This ransomware implementation is provided for educational and research purposes only. Any illegal or unethical use of this code is strictly prohibited. The author takes no responsibility for any damages or legal consequences resulting from the use of this code. USE IT AT YOUR OWN RISK.
