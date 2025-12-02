This project demonstrates a complete Inter-Process Communication (IPC) framework using Pipes, System V Message Queues, and System V Shared Memory in C on a Linux environment.
It showcases how processes communicate, synchronize, and exchange data, forming the backbone of multitasking in modern operating systems.

🧩 Project Overview

Inter-Process Communication enables processes to share information and coordinate their activities.
This framework provides:

A menu-driven interface

Clean implementation of three IPC mechanisms

A central logging system for debugging

Real-world style examples with parent-child processes

Safe cleanup of all IPC resources

🚀 Features
✔ Pipe Communication (POSIX Pipes)

Unidirectional data transfer between parent and child processes using:

pipe()

fork()

read()

write()

Useful for simple command pipelines (e.g., ls | grep txt).

✔ Message Queue Communication (System V)

Supports asynchronous communication between processes using:

msgget()

msgsnd()

msgrcv()

This is similar to how servers handle queued tasks in microservice architecture.

✔ Shared Memory Communication (System V)

Fastest IPC method.
Processes read/write to the same memory region using:

shmget()

shmat()

shmdt()

Widely used in games, sensor systems, and real-time applications.

✔ Logging System

All events are stored in ipc_log.txt, including:

Message sent/received

Shared memory writes/reads

Pipe communication events

Errors with timestamps

This helps with debugging and report documentation.

🏗 System Architecture
                 ┌─────────────────────────┐
                 │       Main Menu         │
                 └───────────┬─────────────┘
                             │
      ┌──────────────────────┼────────────────────────┐
      │                      │                        │
      ▼                      ▼                        ▼
┌────────────┐       ┌──────────────┐        ┌────────────────┐
│  Pipe IPC  │       │ MessageQueue │        │ Shared Memory  │
└────────────┘       └──────────────┘        └────────────────┘
      │                      │                        │
      ▼                      ▼                        ▼
    Send/Read            Send/Receive             Write/Read
      │                      │                        │
      └──────────────→ Logging System ←──────────────┘

📌 Use Cases / Applications
✔ Operating Systems

Used internally by OS to manage multitasking and system processes.

✔ Client–Server Communication

Message queues represent task queues used by:

Amazon backend

Banking systems

Chat systems

✔ Real-time Data Sharing

Shared memory is used in:

Video games (fast rendering)

Robotics

Sensor systems

✔ Shell Commands

Pipes enable commands like:

ps aux | grep chrome

🛠 How to Build and Run
1️⃣ Install GCC (if needed)
sudo apt update
sudo apt install build-essential -y

2️⃣ Create project folder
mkdir ipc_project
cd ipc_project

3️⃣ Create ftok() key files
touch msgfile shmfile

4️⃣ Save the source code as ipc.c
5️⃣ Compile
gcc ipc.c -o ipc

6️⃣ Run
./ipc

7️⃣ View logs
cat ipc_log.txt

🧠 Technical Concepts Used
🔹 Pipes

Simple data flow — parent writes → child reads
Used for:

Shell pipelines

Real-time process output

🔹 Message Queues

Buffered messages; processes communicate even if not running at same time.

🔹 Shared Memory

Fastest method; both processes read/write simultaneously with minimal overhead.

🔹 Logging

Used to trace flow, identify failures, and debug IPC behavior.

🔐 Security Considerations

IPC can be targeted by:

Race conditions

Unauthorized access

Data corruption

Possible enhancements:

Add semaphores for synchronization

Encrypt shared memory regions

Add authentication for message queues

🌟 Future Enhancements

Add POSIX Shared Memory (shm_open)

Add POSIX Message Queues (mq_open)

Add binary and counting semaphores

Add full client–server model using IPC

Build a GUI to visualize IPC communication

Add multithreading support

📚 Learning Outcomes

By using this framework, you learn:

How Linux processes communicate

How system calls work in real-time

How to prevent race conditions

How shared memory and message queues function internally

How to design modular system programs

📜 License

Free to use for educational and research purposes.

🎉 Conclusion

This project provides a hands-on, practical demonstration of how IPC works in Linux.
It is ideal for OS labs, coursework, system programming practice, and building larger multitasking applications.
