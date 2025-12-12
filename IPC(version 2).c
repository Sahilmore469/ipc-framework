

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
#include <arpa/inet.h>
#include <fcntl.h>
#include <sys/stat.h>

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/crypto.h>

#define GCM_IV_LEN 12
#define GCM_TAG_LEN 16

/* DEMO KEY (replace in production with secure key management) */
static const unsigned char DEMO_KEY[32] = "0123456789abcdef0123456789abcdef";

/* Message queue message structure */
struct mq_msg {
    long mtype;
    char mtext[4096];
};

/* Shared memory area structure */
struct shm_area {
    volatile int ready_parent; /* parent wrote */
    volatile int ready_child;  /* child wrote */
    uint32_t ct_len;           /* total bytes written into buf */
    unsigned char buf[3800];   /* stores iv|tag|netlen|ciphertext */
};

/* Logging helper */
static void log_event(const char *msg) {
    FILE *f = fopen("ipc_both_log.txt","a");
    if (!f) return;
    time_t t = time(NULL);
    struct tm tm;
    char ts[64] = {0};
    if (localtime_r(&t, &tm)) strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S", &tm);
    fprintf(f, "%s | %s\n", ts, msg);
    fclose(f);
}

/* Robust read_all/write_all for pipes (not used for MQ/SHM here, but keep) */
static ssize_t write_all(int fd, const void *buf, size_t count) {
    const unsigned char *p = buf;
    size_t left = count;
    while (left) {
        ssize_t w = write(fd, p, left);
        if (w < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        left -= (size_t)w;
        p += w;
    }
    return (ssize_t)count;
}
static ssize_t read_all(int fd, void *buf, size_t count) {
    unsigned char *p = buf;
    size_t left = count;
    while (left) {
        ssize_t r = read(fd, p, left);
        if (r < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        if (r == 0) break;
        left -= (size_t)r;
        p += r;
    }
    return (ssize_t)(count - left);
}

/* AES-256-GCM helpers (EVP) */
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
    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL)) goto done;
    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv_len, NULL)) goto done;
    if (1 != EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv)) goto done;
    if (plaintext_len > 0) {
        if (1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len)) goto done;
        ciphertext_len = len;
    }
    if (1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) goto done;
    ciphertext_len += len;
    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, GCM_TAG_LEN, tag)) goto done;
    ret = ciphertext_len;
done:
    if (ctx) EVP_CIPHER_CTX_free(ctx);
    return ret;
}

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
    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL)) goto done;
    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv_len, NULL)) goto done;
    if (1 != EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv)) goto done;
    if (ciphertext_len > 0) {
        if (1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len)) goto done;
        plaintext_len = len;
    }
    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, GCM_TAG_LEN, (void *)tag)) goto done;
    if (1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len)) goto done;
    plaintext_len += len;
    ret = plaintext_len;
done:
    if (ctx) EVP_CIPHER_CTX_free(ctx);
    return ret;
}

/* Utility: get user input line trimmed */
static void get_user_line(const char *prompt, char *buf, size_t bufsz) {
    printf("%s", prompt);
    fflush(stdout);
    if (!fgets(buf, (int)bufsz, stdin)) {
        buf[0] = '\0';
        return;
    }
    size_t L = strlen(buf);
    if (L && buf[L-1] == '\n') buf[L-1] = '\0';
}

/* Pack encrypted blob into buffer: IV(12)|TAG(16)|NETLEN(4)|CIPHERTEXT */
static size_t pack_encrypted(unsigned char *dst, unsigned char *iv, unsigned char *tag, uint32_t ctlen, unsigned char *ciphertext) {
    size_t off = 0;
    memcpy(dst + off, iv, GCM_IV_LEN); off += GCM_IV_LEN;
    memcpy(dst + off, tag, GCM_TAG_LEN); off += GCM_TAG_LEN;
    uint32_t netlen = htonl(ctlen);
    memcpy(dst + off, &netlen, sizeof(netlen)); off += sizeof(netlen);
    memcpy(dst + off, ciphertext, ctlen); off += ctlen;
    return off;
}

/* Unpack encrypted blob from source; returns ctlen via out_ctlen. */
static int unpack_and_decrypt(unsigned char *src, size_t src_len, unsigned char *out_plain, int *out_plain_len) {
    size_t off = 0;
    if (src_len < GCM_IV_LEN + GCM_TAG_LEN + sizeof(uint32_t)) return -1;
    unsigned char iv[GCM_IV_LEN], tag[GCM_TAG_LEN];
    memcpy(iv, src + off, GCM_IV_LEN); off += GCM_IV_LEN;
    memcpy(tag, src + off, GCM_TAG_LEN); off += GCM_TAG_LEN;
    uint32_t netlen;
    memcpy(&netlen, src + off, sizeof(netlen)); off += sizeof(netlen);
    uint32_t ct_len = ntohl(netlen);
    if (off + ct_len > src_len) return -1;
    unsigned char *ciphertext = src + off;
    int ptlen = aes_gcm_decrypt(ciphertext, (int)ct_len, DEMO_KEY, iv, GCM_IV_LEN, tag, out_plain);
    if (ptlen < 0) return -1;
    *out_plain_len = ptlen;
    return 0;
}

/* Main logic: parent sends message via BOTH MQ and SHM; child receives both; replies via both. */
int main(void) {
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    /* Ensure msgfile and shmfile exist (ftok uses them) */
    /* (user should create them with touch msgfile shmfile before running) */

    /* Create message queue */
    key_t mq_key = ftok("msgfile", 65);
    if (mq_key == (key_t)-1) {
        log_event("ERROR: ftok(msgfile) failed");
        perror("ftok msgfile");
        return 1;
    }
    int qid = msgget(mq_key, 0666 | IPC_CREAT);
    if (qid == -1) {
        log_event("ERROR: msgget failed");
        perror("msgget");
        return 1;
    }


    /* Create shared memory */
    key_t shm_key = ftok("shmfile", 66);
    if (shm_key == (key_t)-1) {
        perror("ftok shmfile");
        msgctl(qid, IPC_RMID, NULL);
        return 1;
    }
    int shmid = shmget(shm_key, sizeof(struct shm_area), 0666 | IPC_CREAT);
    if (shmid == -1) {
        log_event("ERROR: shmget failed");
        perror("shmget");
        msgctl(qid, IPC_RMID, NULL);
        return 1;
    }

    struct shm_area *area = shmat(shmid, NULL, 0);
    if (area == (void*)-1) {
        perror("shmat");
        msgctl(qid, IPC_RMID, NULL);
        shmctl(shmid, IPC_RMID, NULL);
        return 1;
    }

    /* initialize shm flags */
    area->ready_parent = 0;
    area->ready_child = 0;
    area->ct_len = 0;

    pid_t pid = fork();
    if (pid < 0) {
        perror("fork");
        shmdt(area);
        msgctl(qid, IPC_RMID, NULL);
        shmctl(shmid, IPC_RMID, NULL);
        return 1;
    }

    if (pid == 0) {
        /* ---------------- CHILD ----------------
           Child receives the message via BOTH MQ and SHM, decrypts both, prints both,
           prompts for reply, then sends reply via both MQ (mtype=2) and SHM (ready_child=1).
        */
        /* 1) Receive from message queue (mtype=1) - blocking */
        struct mq_msg mq_in;
        ssize_t recvd = msgrcv(qid, &mq_in, sizeof(mq_in.mtext), 1, 0);
        if (recvd == -1) {
            perror("child msgrcv");
            _exit(1);
        }
        int ptlen1 = 0;
        unsigned char plain1[3500];
        if (unpack_and_decrypt((unsigned char*)mq_in.mtext, (size_t)recvd, plain1, &ptlen1) == 0) {
            plain1[ptlen1] = '\0';
            printf("Child received via Message Queue: %s\n", plain1);
        } else {
            fprintf(stderr, "Child: failed to decrypt MQ message\n");
        }

        /* 2) Receive from shared memory: wait until parent sets ready_parent */
        while (area->ready_parent == 0) usleep(1000);
        /* read area->buf up to area->ct_len */
        int ptlen2 = 0;
        unsigned char plain2[3500];
        if ((int)area->ct_len <= 0) {
            fprintf(stderr, "Child: SHM ct_len invalid\n");
        } else {
            if (unpack_and_decrypt(area->buf, (size_t)area->ct_len, plain2, &ptlen2) == 0) {
                plain2[ptlen2] = '\0';
                printf("Child received via Shared Memory: %s\n", plain2);
            } else {
                fprintf(stderr, "Child: failed to decrypt SHM message\n");
            }
        }
        /* clear the parent's ready flag to indicate we consumed it */
        area->ready_parent = 0;

        /* 3) Child prompts for reply */
        char reply[2048];
        get_user_line("Child: Type reply to send via BOTH MQ and SHM: ", reply, sizeof(reply));
        if (reply[0] == '\0') strncpy(reply, "(empty)", sizeof(reply)-1);

        /* 4) Child send via Message Queue (mtype=2) */
        unsigned char iv_c1[GCM_IV_LEN], tag_c1[GCM_TAG_LEN], ciphertext_c1[3000];
        if (1 != RAND_bytes(iv_c1, sizeof(iv_c1))) { perror("RAND_bytes child"); _exit(1); }
        int ctlen_c1 = aes_gcm_encrypt((unsigned char*)reply, (int)strlen(reply), DEMO_KEY, iv_c1, GCM_IV_LEN, ciphertext_c1, tag_c1);
        if (ctlen_c1 < 0) { fprintf(stderr, "Child: MQ encrypt failed\n"); _exit(1); }
        struct mq_msg mq_out;
        mq_out.mtype = 2;
        size_t outoff = pack_encrypted((unsigned char*)mq_out.mtext, iv_c1, tag_c1, (uint32_t)ctlen_c1, ciphertext_c1);
        if (msgsnd(qid, &mq_out, outoff, 0) == -1) {
            perror("child msgsnd");
            _exit(1);
        }

        /* 5) Child send via Shared Memory: pack into area->buf and set ready_child = 1 */
        unsigned char iv_c2[GCM_IV_LEN], tag_c2[GCM_TAG_LEN], ciphertext_c2[3000];
        if (1 != RAND_bytes(iv_c2, sizeof(iv_c2))) { perror("RAND_bytes child2"); _exit(1); }
        int ctlen_c2 = aes_gcm_encrypt((unsigned char*)reply, (int)strlen(reply), DEMO_KEY, iv_c2, GCM_IV_LEN, ciphertext_c2, tag_c2);
        if (ctlen_c2 < 0) { fprintf(stderr, "Child: SHM encrypt failed\n"); _exit(1); }
        size_t off2 = pack_encrypted(area->buf, iv_c2, tag_c2, (uint32_t)ctlen_c2, ciphertext_c2);
        area->ct_len = (uint32_t)off2;
        /* signal parent that child reply is ready */
        area->ready_child = 1;

        /* done (child) */
        shmdt(area);
        _exit(0);
    } else {
        /* ---------------- PARENT ----------------
           Parent prompts for message, sends the SAME encrypted message via BOTH MQ (mtype=1) and SHM (ready_parent=1),
           then waits for both replies (MQ mtype=2 and SHM ready_child==1), decrypts and prints both, then cleanup.
        */
        char message[2048];
        get_user_line("Parent: Type message to send via BOTH MQ and SHM: ", message, sizeof(message));
        if (message[0] == '\0') strncpy(message, "(empty)", sizeof(message)-1);

        /* 1) Pack & send via Message Queue (mtype=1) */
        unsigned char iv_p1[GCM_IV_LEN], tag_p1[GCM_TAG_LEN], ciphertext_p1[3000];
        if (1 != RAND_bytes(iv_p1, sizeof(iv_p1))) { perror("RAND_bytes parent"); }
        int ctlen_p1 = aes_gcm_encrypt((unsigned char*)message, (int)strlen(message), DEMO_KEY, iv_p1, GCM_IV_LEN, ciphertext_p1, tag_p1);
        if (ctlen_p1 < 0) { fprintf(stderr, "Parent: MQ encrypt failed\n"); }
        struct mq_msg outp;
        outp.mtype = 1;
        size_t outlen = pack_encrypted((unsigned char*)outp.mtext, iv_p1, tag_p1, (uint32_t)ctlen_p1, ciphertext_p1);
        if (msgsnd(qid, &outp, outlen, 0) == -1) {
            perror("parent msgsnd");
        }

        /* 2) Pack & send via Shared Memory: copy into area->buf and set ready_parent=1 */
        unsigned char iv_p2[GCM_IV_LEN], tag_p2[GCM_TAG_LEN], ciphertext_p2[3000];
        if (1 != RAND_bytes(iv_p2, sizeof(iv_p2))) { perror("RAND_bytes parent2"); }
        int ctlen_p2 = aes_gcm_encrypt((unsigned char*)message, (int)strlen(message), DEMO_KEY, iv_p2, GCM_IV_LEN, ciphertext_p2, tag_p2);
        if (ctlen_p2 < 0) { fprintf(stderr, "Parent: SHM encrypt failed\n"); }
        size_t offp = pack_encrypted(area->buf, iv_p2, tag_p2, (uint32_t)ctlen_p2, ciphertext_p2);
        area->ct_len = (uint32_t)offp;
        /* signal child */
        area->ready_parent = 1;

        /* Now wait for child's replies:
           - Message Queue (mtype=2) blocking receive
           - Shared Memory: poll area->ready_child
        */

        /* A) wait for MQ reply (mtype=2) */
        struct mq_msg mq_reply;
        ssize_t r = msgrcv(qid, &mq_reply, sizeof(mq_reply.mtext), 2, 0);
        if (r == -1) {
            perror("parent msgrcv");
        } else {
            int ptlen_r1 = 0;
            unsigned char plain_r1[3500];
            if (unpack_and_decrypt((unsigned char*)mq_reply.mtext, (size_t)r, plain_r1, &ptlen_r1) == 0) {
                plain_r1[ptlen_r1] = '\0';
                printf("Parent received via Message Queue (child->parent): %s\n", plain_r1);
            } else {
                fprintf(stderr, "Parent: failed to decrypt MQ reply\n");
            }
        }

        /* B) wait for SHM reply (area->ready_child) */
        while (area->ready_child == 0) usleep(1000);
        if (area->ct_len <= 0) {
            fprintf(stderr, "Parent: SHM ct_len invalid\n");
        } else {
            int ptlen_r2 = 0;
            unsigned char plain_r2[3500];
            if (unpack_and_decrypt(area->buf, (size_t)area->ct_len, plain_r2, &ptlen_r2) == 0) {
                plain_r2[ptlen_r2] = '\0';
                printf("Parent received via Shared Memory (child->parent): %s\n", plain_r2);
            } else {
                fprintf(stderr, "Parent: failed to decrypt SHM reply\n");
            }
        }
        /* clear flag */
        area->ready_child = 0;

        /* cleanup */
        waitpid(pid, NULL, 0);
        shmdt(area);
        msgctl(qid, IPC_RMID, NULL);
        shmctl(shmid, IPC_RMID, NULL);
    }

    /* OpenSSL cleanup */
    EVP_cleanup();
    CRYPTO_cleanup_all_ex_data();
    ERR_free_strings();
    return 0;
}
