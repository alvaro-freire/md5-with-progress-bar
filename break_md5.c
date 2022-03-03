#include <sys/types.h>
#include <pthread.h>
#include <unistd.h>
#include <openssl/md5.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define PASS_LEN 6
#define BAR_LEN 50

struct args {
    unsigned char *md5;
    unsigned char *pass;
    long *progress;
    int *finish;
};

struct thread_info {
    pthread_t id;    // id returned by pthread_create()
    struct args *args;  // pointer to the arguments
};

long ipow(long base, int exp) {
    long res = 1;

    for (;;) {
        if (exp & 1) {
            res *= base;
        }
        exp >>= 1;
        if (!exp) {
            break;
        }
        base *= base;
    }

    return res;
}

long pass_to_long(char *str) {
    long res = 0;

    for (int i = 0; i < PASS_LEN; i++) {
        res = res * 26 + str[i] - 'a';
    }

    return res;
}

void long_to_pass(long n, unsigned char *str) {  // str should have size PASS_SIZE+1
    for (int i = PASS_LEN - 1; i >= 0; i--) {
        str[i] = n % 26 + 'a';
        n /= 26;
    }
    str[PASS_LEN] = '\0';
}

int hex_value(char c) {
    if (c >= '0' && c <= '9') {
        return c - '0';
    } else if (c >= 'A' && c <= 'F') {
        return c - 'A' + 10;
    } else if (c >= 'a' && c <= 'f') {
        return c - 'a' + 10;
    } else {
        return 0;
    }
}

void hex_to_num(char *str, unsigned char *hex) {
    for (int i = 0; i < MD5_DIGEST_LENGTH; i++) {
        hex[i] = (hex_value(str[i * 2]) << 4) + hex_value(str[i * 2 + 1]);
    }
}

void *print_progress(void *ptr){
    struct args *args = ptr;
    long bound = ipow(26, PASS_LEN);
    int n;
    char *bar = "##################################################";
    char *dot = "..................................................";
    float per;

    while (*args->finish != 1) {
        n = ((*args->progress) / (float) bound) * BAR_LEN; // update progress
        per = ((*args->progress) / (float) bound) * 100;

        printf("\r[Progress: %2.0f%%] [%.*s \b%.*s]", per, n, bar, BAR_LEN - n, dot);
        fflush(stdout);

        sleep(1);
    }

    return NULL;
}

void *break_pass(void *ptr) {
    struct args *args = ptr;
    unsigned char res[MD5_DIGEST_LENGTH];
    long bound = ipow(26, PASS_LEN);

    for (;*args->progress < bound; (*args->progress)++) {

        long_to_pass(*args->progress, args->pass);

        MD5(args->pass, PASS_LEN, res);

        if (0 == memcmp(res, args->md5, MD5_DIGEST_LENGTH)) {
            printf("\n");
            break; // Found it!
        }
    }

    *args->finish = 1; // flag for progress thread to stop

    return NULL;
}

struct thread_info *start_thread(unsigned char *md5_num, int *finish, long *progress, void *(operation)(void *)) {
    struct thread_info *thread = malloc(sizeof (struct thread_info));

    thread->args = malloc(sizeof (struct args));
    thread->args->pass = malloc((PASS_LEN + 1) * sizeof(char));
    thread->args->md5 = md5_num;
    thread->args->finish = finish;
    thread->args->progress = progress;

    if (0 != pthread_create(&thread->id, NULL, operation, thread->args)) {
        printf("Could not create thread\n");
        exit(1);
    }

    return thread;
}

void free_thread(struct thread_info *thread) {
    free(thread->args->pass);
    free(thread->args);
    free(thread);
}

int main(int argc, char *argv[]) {
    struct thread_info *calc; // thread for calculations
    struct thread_info *progress; // thread for progress bar
    int *finish = malloc(sizeof (int));
    long *prog = malloc(sizeof (long));

    if (argc < 2) {
        printf("Use: %s string\n", argv[0]);
        exit(0);
    }

    unsigned char md5_num[MD5_DIGEST_LENGTH];
    hex_to_num(argv[1], md5_num);

    *finish = 0;
    *prog = 0;
    progress = start_thread(md5_num, finish, prog, print_progress);
    calc = start_thread(md5_num, finish, prog, break_pass);

    pthread_join(progress->id, NULL);
    pthread_join(calc->id, NULL);

    printf("%s: %s\n", argv[1], calc->args->pass);

    free_thread(progress);
    free_thread(calc);
    free(finish);
    free(prog);

    return 0;
}
