🔐 Encrypted Inter-Process Communication (IPC) Framework
Pipes | Message Queues | Shared Memory | AES-256-GCM Security

This project implements a secure, modular, and unified Inter-Process Communication (IPC) Framework using C, POSIX APIs, and OpenSSL.
It integrates Pipes, Message Queues, and Shared Memory under a single structure and adds AES-256-GCM encryption to ensure confidentiality and integrity of all process-to-process communication.

🚀 Features
✅ Core IPC Communication

Full support for:

Pipes

Message Queues

Shared Memory

Unified API for all three mechanisms

Automatic packing/unpacking of encrypted data

🔐 Security Layer

AES-256-GCM encryption and decryption

Random IV generation using OpenSSL RAND_bytes()

GCM authentication tag for tamper detection

Secure message handling (IV | TAG | LENGTH | CIPHERTEXT)

Logging of all events to ipc_log.txt

👁 Management & Monitoring

Menu-driven interface

Displays decrypted output to user

Tracks:

Sent messages

Received messages

Encryption/decryption success or failure

📂 Project Structure
📦 Encrypted-IPC-Framework
│
├── ipc_encrypted.c          # Main implementation
├── ipc_log.txt              # Runtime logs
├── msgfile                  # ftok file for Message Queue
├── shmfile                  # ftok file for Shared Memory
└── README.md                # Project documentation

🧩 System Architecture

Modules included:

IPC Core Communication Engine

Security & Encryption Layer (AES-256-GCM)

Management & Monitoring Interface

All IPC operations follow the flow:

User Input → Security Layer → IPC Engine → Processes → Output → Logs

📦 Requirements

Linux-based OS (Ubuntu, Fedora, Kali, etc.)

GCC Compiler

OpenSSL development libraries

Install OpenSSL:

sudo apt install libssl-dev

🛠 Compilation & Execution
Compile:
gcc ipc.c -o ipc -lcrypto

Run the program:
./ipc

Menu Options:
1 → Pipe Communication
2 → Message Queue
3 → Shared Memory


Each selection performs an encrypted IPC transfer and prints the decrypted output.

🧪 Example Output
===== IPC Framework Menu (Encrypted) =====
1. Pipe Communication
2. Message Queue
3. Shared Memory
Enter Choice → 1

PIPE Received → Hello from Child using PIPE

📊 Logging

All communication events are stored in:

ipc_log.txt


Events include:

Encrypted message sent

Decrypted message received

Unauthorized access attempt

Encryption/Decryption failure

🔧 Technologies Used

C Programming Language

POSIX IPC (pipe, msgget, shmget, etc.)

OpenSSL EVP API

GCC / GDB

Linux system calls

Makefile (optional)

🛡 Security Details

This framework uses:

AES-256-GCM encryption

32-byte encryption key

12-byte IV

16-byte authentication tag

Resistance against:

Replay attacks

Data tampering

Unauthorized reading

🧭 Future Enhancements

Dynamic key exchange (Diffie-Hellman / RSA)

Cross-machine IPC via sockets

GUI-based monitoring dashboard

Shared library conversion (.so)

Real-time message prioritization

Integration with Docker for sandbox testing



👤 Author

Sahil Santosh More
B.Tech CSE – Lovely Professional University
2025

📜 License

This project is for educational and research purposes.
You may modify or extend it freely.
