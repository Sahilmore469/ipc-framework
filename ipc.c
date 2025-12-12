#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <sys/shm.h>
#include <sys/stat.h>
#include <arpa/inet.h>   // htonl / ntohl

/* OpenSSL */
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>

#define GCM_IV_LEN 12
#define GCM_TAG_LEN 16

/* Demo AES-256 key (32 bytes) - replace with secure key management in real use */
static const unsigned char DEMO_KEY[32] = "0123456789abcdef0123456789abcdef";

/* ---------------------- Logging helper ----------------------- */
static void log_event(const char *msg) {
    FILE *f = fopen("ipc_log.txt", "a");
    if (!f) return;
    time_t t = time(NULL);
    char *time_str = ctime(&t);
    if (time_str)
        fprintf(f, "%s | %s", time_str, msg);
    else
        fprintf(f, "UNKNOWN_TIME | %s", msg);
    fclose(f);
}

/* ---------------- AES-256-GCM helpers (OpenSSL EVP) ------------- */
/* Returns ciphertext length on success, -1 on error */
static int aes_gcm_encrypt(
    const unsigned char *plaintext, int plaintext_len,
    const unsigned char *key,
    unsigned char *iv, int iv_len,
    unsigned char *ciphertext,
    unsigned char *tag)
{
    EVP_CIPHER_CTX *ctx = NULL;
    int len = 0, ciphertext_len = 0, ret = -1;

    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) goto done;

    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL))
        goto done;

    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv_len, NULL))
        goto done;

    if (1 != EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv)) goto done;

    if (1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
        goto done;
    ciphertext_len = len;

    if (1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) goto done;
    ciphertext_len += len;

    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, GCM_TAG_LEN, tag))
        goto done;

    ret = ciphertext_len;

done:
    if (ctx) EVP_CIPHER_CTX_free(ctx);
    return ret;
}

/* Returns plaintext length on success, -1 on error or tag mismatch */
static int aes_gcm_decrypt(
    const unsigned char *ciphertext, int ciphertext_len,
    const unsigned char *key,
    const unsigned char *iv, int iv_len,
    const unsigned char *tag,
    unsigned char *plaintext)
{
    EVP_CIPHER_CTX *ctx = NULL;
    int len = 0, plaintext_len = 0, ret = -1;

    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) goto done;

    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL))
        goto done;

    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv_len, NULL))
        goto done;

    if (1 != EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv)) goto done;

    if (1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
        goto done;
    plaintext_len = len;

    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, GCM_TAG_LEN, (void *)tag))
        goto done;

    if (1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len)) goto done;
    plaintext_len += len;

    ret = plaintext_len;

done:
    if (ctx) EVP_CIPHER_CTX_free(ctx);
    return ret;
}

/* ---------------------- PIPE DEMO (encrypted) ----------------------------- */
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
        close(fd[0]); close(fd[1]);
        return;
    }

    if (pid == 0) {
        /* Child: encrypt and write */
        const char *msg = "Hello from Child using PIPE";
        unsigned char iv[GCM_IV_LEN];
        unsigned char tag[GCM_TAG_LEN];
        unsigned char ciphertext[512];
        int ct_len;

        if (1 != RAND_bytes(iv, sizeof(iv))) {
            perror("RAND_bytes");
            log_event("PIPE : RAND_bytes failed\n");
            _exit(EXIT_FAILURE);
        }

        ct_len = aes_gcm_encrypt((unsigned char*)msg, (int)strlen(msg),
                                 DEMO_KEY, iv, sizeof(iv),
                                 ciphertext, tag);
        if (ct_len < 0) {
            fprintf(stderr, "Encryption failed (pipe)\n");
            log_event("PIPE : Encryption failed\n");
            _exit(EXIT_FAILURE);
        }

        /* Send: IV | TAG | CTLEN(4 bytes network order) | CIPHERTEXT */
        uint32_t netlen = htonl((uint32_t)ct_len);
        if (write(fd[1], iv, sizeof(iv)) == -1) perror("write iv");
        if (write(fd[1], tag, sizeof(tag)) == -1) perror("write tag");
        if (write(fd[1], &netlen, sizeof(netlen)) == -1) perror("write len");
        if (write(fd[1], ciphertext, ct_len) == -1) {
            perror("write ct");
            log_event("PIPE : Failed to write message\n");
        } else {
            log_event("PIPE : Encrypted message sent\n");
        }

        close(fd[1]);
        _exit(EXIT_SUCCESS);
    } else {
        /* Parent: read, decrypt and print */
        unsigned char iv[GCM_IV_LEN], tag[GCM_TAG_LEN];
        uint32_t netlen;
        uint32_t ct_len;
        unsigned char ciphertext[512], plaintext[512];

        close(fd[1]);
        if (read(fd[0], iv, sizeof(iv)) != sizeof(iv)) {
            perror("read iv");
            log_event("PIPE : Failed to read iv\n");
        }
        if (read(fd[0], tag, sizeof(tag)) != sizeof(tag)) {
            perror("read tag");
            log_event("PIPE : Failed to read tag\n");
        }
        if (read(fd[0], &netlen, sizeof(netlen)) != sizeof(netlen)) {
            perror("read len");
            log_event("PIPE : Failed to read len\n");
        }
        ct_len = ntohl(netlen);
        if (ct_len > sizeof(ciphertext)) {
            fprintf(stderr, "Ciphertext too large (pipe)\n");
            log_event("PIPE : Ciphertext too large\n");
            close(fd[0]);
            waitpid(pid, NULL, 0);
            return;
        }
        if (read(fd[0], ciphertext, ct_len) != (ssize_t)ct_len) {
            perror("read ct");
            log_event("PIPE : Failed to read ciphertext\n");
        } else {
            int ptlen = aes_gcm_decrypt(ciphertext, (int)ct_len, DEMO_KEY,
                                       iv, sizeof(iv), tag, plaintext);
            if (ptlen < 0) {
                fprintf(stderr, "Decryption failed or tag mismatch (pipe)\n");
                log_event("PIPE : Decryption failed\n");
            } else {
                plaintext[ptlen] = '\0';
                printf("PIPE Received → %s\n", plaintext);
                log_event("PIPE : Encrypted message received and decrypted\n");
            }
        }
        close(fd[0]);
        waitpid(pid, NULL, 0);
    }
}

/* ------------------ MESSAGE QUEUE DEMO (encrypted) ------------------------ */
struct msgbuf {
    long mtype;
    char mtext[1024]; /* large enough to hold iv+tag+len+ciphertext */
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
        /* Child: encrypt and send */
        const char *msg = "Hello using Message Queue";
        unsigned char iv[GCM_IV_LEN], tag[GCM_TAG_LEN];
        unsigned char ciphertext[800];
        int ct_len;

        if (1 != RAND_bytes(iv, sizeof(iv))) {
            perror("RAND_bytes");
            _exit(EXIT_FAILURE);
        }

        ct_len = aes_gcm_encrypt((unsigned char*)msg, (int)strlen(msg),
                                 DEMO_KEY, iv, sizeof(iv),
                                 ciphertext, tag);
        if (ct_len < 0) {
            fprintf(stderr, "Encryption failed (msgq)\n");
            _exit(EXIT_FAILURE);
        }

        struct msgbuf m;
        m.mtype = 1;
        size_t offset = 0;
        memcpy(m.mtext + offset, iv, GCM_IV_LEN); offset += GCM_IV_LEN;
        memcpy(m.mtext + offset, tag, GCM_TAG_LEN); offset += GCM_TAG_LEN;
        uint32_t netlen = htonl((uint32_t)ct_len);
        memcpy(m.mtext + offset, &netlen, sizeof(netlen)); offset += sizeof(netlen);
        memcpy(m.mtext + offset, ciphertext, ct_len); offset += ct_len;

        if (msgsnd(qid, &m, offset, 0) == -1) {
            perror("msgsnd");
            log_event("MSG_QUEUE : Failed to send message\n");
        } else {
            log_event("MSG_QUEUE : Encrypted message sent\n");
        }

        _exit(EXIT_SUCCESS);
    } else {
        /* Parent: receive and decrypt */
        struct msgbuf m;
        if (msgrcv(qid, &m, sizeof(m.mtext), 1, 0) == -1) {
            perror("msgrcv");
            log_event("MSG_QUEUE : Failed to receive message\n");
        } else {
            size_t offset = 0;
            unsigned char iv[GCM_IV_LEN], tag[GCM_TAG_LEN];
            uint32_t netlen, ct_len;
            unsigned char ciphertext[800], plaintext[800];

            memcpy(iv, m.mtext + offset, GCM_IV_LEN); offset += GCM_IV_LEN;
            memcpy(tag, m.mtext + offset, GCM_TAG_LEN); offset += GCM_TAG_LEN;
            memcpy(&netlen, m.mtext + offset, sizeof(netlen)); offset += sizeof(netlen);
            ct_len = ntohl(netlen);
            if (ct_len > sizeof(ciphertext)) {
                fprintf(stderr, "Ciphertext too large (msgq)\n");
                log_event("MSG_QUEUE : Ciphertext too large\n");
            } else {
                memcpy(ciphertext, m.mtext + offset, ct_len);
                int ptlen = aes_gcm_decrypt(ciphertext, (int)ct_len, DEMO_KEY,
                                           iv, sizeof(iv), tag, plaintext);
                if (ptlen < 0) {
                    fprintf(stderr, "Decryption failed or tag mismatch (msgq)\n");
                    log_event("MSG_QUEUE : Decryption failed\n");
                } else {
                    plaintext[ptlen] = '\0';
                    printf("Message Queue Received → %s\n", plaintext);
                    log_event("MSG_QUEUE : Encrypted message received and decrypted\n");
                }
            }
        }
        msgctl(qid, IPC_RMID, NULL);
        waitpid(pid, NULL, 0);
    }
}

/* ------------------ SHARED MEMORY DEMO (encrypted) ------------------------ */
static void shared_memory_demo(void) {
    key_t key = ftok("shmfile", 65);
    if (key == -1) {
        perror("ftok (shmfile)");
        log_event("SHM : ftok() failed\n");
        return;
    }

    /* allocate larger to hold iv+tag+len+ct */
    int shmid = shmget(key, 4096, 0666 | IPC_CREAT);
    if (shmid == -1) {
        perror("shmget");
        log_event("SHM : shmget() failed\n");
        return;
    }

    unsigned char *data = (unsigned char *)shmat(shmid, NULL, 0);
    if (data == (unsigned char *)(-1)) {
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
        /* Child: encrypt and write into shared memory */
        const char *msg = "Hello using Shared Memory";
        unsigned char iv[GCM_IV_LEN], tag[GCM_TAG_LEN];
        unsigned char ciphertext[2048];
        int ct_len;

        if (1 != RAND_bytes(iv, sizeof(iv))) {
            perror("RAND_bytes");
            _exit(EXIT_FAILURE);
        }

        ct_len = aes_gcm_encrypt((unsigned char*)msg, (int)strlen(msg),
                                 DEMO_KEY, iv, sizeof(iv),
                                 ciphertext, tag);
        if (ct_len < 0) {
            fprintf(stderr, "Encryption failed (shm)\n");
            _exit(EXIT_FAILURE);
        }

        /* Pack into shared memory: IV | TAG | CTLEN(4) | CIPHERTEXT */
        size_t offset = 0;
        memcpy(data + offset, iv, GCM_IV_LEN); offset += GCM_IV_LEN;
        memcpy(data + offset, tag, GCM_TAG_LEN); offset += GCM_TAG_LEN;
        uint32_t netlen = htonl((uint32_t)ct_len);
        memcpy(data + offset, &netlen, sizeof(netlen)); offset += sizeof(netlen);
        memcpy(data + offset, ciphertext, ct_len); offset += ct_len;

        log_event("SHM : Encrypted data written\n");
        _exit(EXIT_SUCCESS);
    } else {
        /* Parent: read, decrypt and print */
        sleep(1); /* naive sync */
        size_t offset = 0;
        unsigned char iv[GCM_IV_LEN], tag[GCM_TAG_LEN];
        uint32_t netlen, ct_len;
        unsigned char ciphertext[2048], plaintext[2048];

        memcpy(iv, data + offset, GCM_IV_LEN); offset += GCM_IV_LEN;
        memcpy(tag, data + offset, GCM_TAG_LEN); offset += GCM_TAG_LEN;
        memcpy(&netlen, data + offset, sizeof(netlen)); offset += sizeof(netlen);
        ct_len = ntohl(netlen);

        if (ct_len > sizeof(ciphertext)) {
            fprintf(stderr, "Ciphertext too large (shm)\n");
            log_event("SHM : Ciphertext too large\n");
        } else {
            memcpy(ciphertext, data + offset, ct_len);
            int ptlen = aes_gcm_decrypt(ciphertext, (int)ct_len, DEMO_KEY,
                                       iv, sizeof(iv), tag, plaintext);
            if (ptlen < 0) {
                fprintf(stderr, "Decryption failed or tag mismatch (shm)\n");
                log_event("SHM : Decryption failed\n");
            } else {
                plaintext[ptlen] = '\0';
                printf("Shared Memory Received → %s\n", plaintext);
                log_event("SHM : Encrypted data read and decrypted\n");
            }
        }

        shmdt(data);
        shmctl(shmid, IPC_RMID, NULL);
        waitpid(pid, NULL, 0);
    }
}

/* --------------------------- MAIN ----------------------------- */
int main(void) {
    /* Initialize OpenSSL (safe for older versions) */
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    int choice;
    printf("\n===== IPC Framework Menu (Encrypted) =====\n");
    printf("1. Pipe Communication\n");
    printf("2. Message Queue\n");
    printf("3. Shared Memory\n");
    printf("Enter Choice → ");

    if (scanf("%d", &choice) != 1) {
        fprintf(stderr, "Invalid input. Exiting.\n");
        return EXIT_FAILURE;
    }

    switch (choice) {
        case 1: pipe_demo(); break;
        case 2: msgq_demo(); break;
        case 3: shared_memory_demo(); break;
        default: printf("Invalid option.\n"); break;
    }

    /* Cleanup OpenSSL */
    EVP_cleanup();
    CRYPTO_cleanup_all_ex_data();
    ERR_free_strings();

    return EXIT_SUCCESS;
}
