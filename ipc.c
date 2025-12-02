
#include <stdio.h>
#include <stdlib.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <sys/shm.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <errno.h>

/* ---------------------- Logging Utility ----------------------- */
static void log_event(const char *msg) {
    FILE *f = fopen("ipc_log.txt", "a");
    if (f == NULL) {
        // If logging fails, we don't exit the program, just silently ignore.
        return;
    }

    time_t t = time(NULL);
    char *time_str = ctime(&t);
    if (time_str != NULL) {
        // ctime() string already has newline at the end
        fprintf(f, "%s | %s", time_str, msg);
    } else {
        fprintf(f, "UNKNOWN_TIME | %s", msg);
    }

    fclose(f);
}

/* ---------------------- PIPE DEMO ----------------------------- */
static void pipe_demo(void) {
    int fd[2];
    pid_t pid;

    if (pipe(fd) == -1) {
        perror("pipe");
        log_event("PIPE : Failed to create pipe\n");
        return;
    }

    pid = fork();
    if (pid < 0) {
        perror("fork");
        log_event("PIPE : fork() failed\n");
        close(fd[0]);
        close(fd[1]);
        return;
    }

    if (pid == 0) {
        /* Child process: writer */
        const char msg[] = "Hello from Child using PIPE";

        close(fd[0]);  // Close unused read end

        if (write(fd[1], msg, sizeof(msg)) == -1) {
            perror("write");
            log_event("PIPE : Failed to write message\n");
        } else {
            log_event("PIPE : Message sent\n");
        }

        close(fd[1]);
        _exit(EXIT_SUCCESS);
    } else {
        /* Parent process: reader */
        char buf[128];
        ssize_t n;

        close(fd[1]);  // Close unused write end

        n = read(fd[0], buf, sizeof(buf));
        if (n == -1) {
            perror("read");
            log_event("PIPE : Failed to read message\n");
        } else {
            buf[(n > 0 && n < (ssize_t)sizeof(buf)) ? n : (ssize_t)sizeof(buf) - 1] = '\0';
            printf("PIPE Received → %s\n", buf);
            log_event("PIPE : Message received\n");
        }

        close(fd[0]);
        waitpid(pid, NULL, 0);
    }
}

/* ------------------ MESSAGE QUEUE DEMO ------------------------ */
struct msgbuf {
    long mtype;
    char mtext[64];
};

static void msgq_demo(void) {
    key_t key = ftok("msgfile", 65);
    if (key == -1) {
        perror("ftok (msgfile)");
        log_event("MSG_QUEUE : ftok() failed\n");
        return;
    }

    int qid = msgget(key, 0666 | IPC_CREAT);
    if (qid == -1) {
        perror("msgget");
        log_event("MSG_QUEUE : msgget() failed\n");
        return;
    }

    pid_t pid = fork();
    if (pid < 0) {
        perror("fork");
        log_event("MSG_QUEUE : fork() failed\n");
        msgctl(qid, IPC_RMID, NULL);
        return;
    }

    if (pid == 0) {
        /* Child: sender */
        struct msgbuf msg;
        msg.mtype = 1;
        snprintf(msg.mtext, sizeof(msg.mtext), "Hello using Message Queue");

        if (msgsnd(qid, &msg, sizeof(msg.mtext), 0) == -1) {
            perror("msgsnd");
            log_event("MSG_QUEUE : Failed to send message\n");
        } else {
            log_event("MSG_QUEUE : Message sent\n");
        }

        _exit(EXIT_SUCCESS);
    } else {
        /* Parent: receiver */
        struct msgbuf msg;

        if (msgrcv(qid, &msg, sizeof(msg.mtext), 1, 0) == -1) {
            perror("msgrcv");
            log_event("MSG_QUEUE : Failed to receive message\n");
        } else {
            printf("Message Queue Received → %s\n", msg.mtext);
            log_event("MSG_QUEUE : Message received\n");
        }

        msgctl(qid, IPC_RMID, NULL);
        waitpid(pid, NULL, 0);
    }
}

/* ------------------ SHARED MEMORY DEMO ------------------------ */
static void shared_memory_demo(void) {
    key_t key = ftok("shmfile", 65);
    if (key == -1) {
        perror("ftok (shmfile)");
        log_event("SHM : ftok() failed\n");
        return;
    }

    int shmid = shmget(key, 1024, 0666 | IPC_CREAT);
    if (shmid == -1) {
        perror("shmget");
        log_event("SHM : shmget() failed\n");
        return;
    }

    char *data = (char *)shmat(shmid, NULL, 0);
    if (data == (char *)(-1)) {
        perror("shmat");
        log_event("SHM : shmat() failed\n");
        return;
    }

    pid_t pid = fork();
    if (pid < 0) {
        perror("fork");
        log_event("SHM : fork() failed\n");
        shmdt(data);
        shmctl(shmid, IPC_RMID, NULL);
        return;
    }

    if (pid == 0) {
        /* Child: writer */
        snprintf(data, 1024, "Hello using Shared Memory");
        log_event("SHM : Data written\n");
        _exit(EXIT_SUCCESS);
    } else {
        /* Parent: reader */
        sleep(1);  // Simple sync: wait for child to write
        printf("Shared Memory Received → %s\n", data);
        log_event("SHM : Data read\n");

        shmdt(data);
        shmctl(shmid, IPC_RMID, NULL);
        waitpid(pid, NULL, 0);
    }
}

/* --------------------------- MAIN ----------------------------- */
int main(void) {
    int choice;

    printf("\n===== IPC Framework Menu =====\n");
    printf("1. Pipe Communication\n");
    printf("2. Message Queue\n");
    printf("3. Shared Memory\n");
    printf("Enter Choice → ");

    if (scanf("%d", &choice) != 1) {
        fprintf(stderr, "Invalid input. Exiting.\n");
        return EXIT_FAILURE;
    }

    switch (choice) {
        case 1:
            pipe_demo();
            break;
        case 2:
            msgq_demo();
            break;
        case 3:
            shared_memory_demo();
            break;
        default:
            printf("Invalid option.\n");
            break;
    }

    return EXIT_SUCCESS;
}
