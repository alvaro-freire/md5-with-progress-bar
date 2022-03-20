#include <sys/types.h>
#include <pthread.h>
#include <unistd.h>
#include <openssl/md5.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define PASS_LEN 6
#define BAR_LEN 50
#define THREADS 4
#define BATCH 10

struct solutions {
    unsigned char *md5;
    unsigned char *pass;
    int done;
};

struct args {
    struct solutions *solutions;
    int n_hashes;
    long *progress; // shared variable for tries
    int *finish; // shared flag
    pthread_mutex_t *mutex_progress;
    pthread_mutex_t *mutex_finish;
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

void *print_progress(void *ptr) {
    struct args *args = ptr;
    long bound = ipow(26, PASS_LEN);
    int n; // number of '#' to print
    int i;
    char bar[BAR_LEN], dot[BAR_LEN];
    float per; // variable for percentage (progress)
    long hashes; // variable to print hashes per second
    int count_hash = 0; // variable to count the hashes per second

    for (i = 0; i < BAR_LEN; ++i) {
        bar[i] = '#';
    }

    for (i = 0; i < BAR_LEN; ++i) {
        dot[i] = '.';
    }

    while (1) {
        i++;
        hashes = *args->progress - count_hash;
        n = ((*args->progress) / (float) bound) * BAR_LEN; // update progress
        per = ((*args->progress) / (float) bound) * 100;

        printf("\r[Progress: %2.0f%%] [%d/%d] [%.*s \b%.*s] %4ldkH/s", per, *args->finish, args->n_hashes, n, bar, BAR_LEN - n, dot, hashes / 1000);
        fflush(stdout);

        count_hash = *args->progress;
        sleep(1);

        if (*args->finish == args->n_hashes || *args->progress >= bound) {
            break;
        }
    }

    printf("\r[Progress: %2.0f%%] [%d/%d] [%.*s \b%.*s] %4ldkH/s", per, *args->finish, args->n_hashes, n, bar, BAR_LEN - n, dot, hashes / 1000);

    printf("\n");

    return NULL;
}

void *break_pass(void *ptr) {
    struct args *args = ptr;
    unsigned char res[MD5_DIGEST_LENGTH];
    long bound = ipow(26, PASS_LEN);
    int number = 0;
    unsigned char *pass = malloc((PASS_LEN + 1) * sizeof (char));

    while (1) {
        pthread_mutex_lock(args->mutex_finish);
        if (*args->progress >= bound || *args->finish == args->n_hashes) {
            pthread_mutex_unlock(args->mutex_finish);
            break;
        }
        pthread_mutex_unlock(args->mutex_finish);

        pthread_mutex_lock(args->mutex_progress); // Inicio sección crítica
        number = *args->progress;
        (*args->progress) += BATCH;
        pthread_mutex_unlock(args->mutex_progress); // Fin sección crítica

        for (int i = 0; i < BATCH; ++i) {
            long_to_pass(number + i, pass);
            MD5(pass, PASS_LEN, res);

            for(int j = 0; j < args->n_hashes; ++j) {
                if (!args->solutions[j].done) {
                    if (0 == memcmp(res, args->solutions[j].md5, MD5_DIGEST_LENGTH)) {
                        pthread_mutex_lock(args->mutex_finish);
                        (*args->finish)++;
                        args->solutions[j].done = 1;
                        memcpy(args->solutions[j].pass, pass, PASS_LEN + 1);
                        pthread_mutex_unlock(args->mutex_finish);
                    }
                }
            }
        }
    }

    free(pass);

    return NULL;
}

// start THREAD threads running on break_pass
struct thread_info *start_threads(struct solutions *solutions, int n_hashes, int *finish, long *progress) {
    struct thread_info *threads = malloc(sizeof(struct thread_info) * THREADS);
    pthread_mutex_t *mutex_progress, *mutex_finish;
    int i;

    mutex_progress = malloc(sizeof(pthread_mutex_t));
    mutex_finish = malloc(sizeof(pthread_mutex_t));

    pthread_mutex_init(mutex_progress, NULL);
    pthread_mutex_init(mutex_finish, NULL);

    for (i = 0; i < THREADS; ++i) {
        threads[i].args = malloc(sizeof(struct args));
        threads[i].args->solutions = solutions;
        threads[i].args->n_hashes = n_hashes;
        threads[i].args->finish = finish;
        threads[i].args->progress = progress;
        threads[i].args->mutex_finish = mutex_finish;
        threads[i].args->mutex_progress = mutex_progress;

        if (0 != pthread_create(&threads[i].id, NULL, break_pass, threads[i].args)) {
            printf("Could not create thread #%d\n", i);
            exit(1);
        }
    }

    return threads;
}

struct thread_info *start_thread(int *finish, int n_hashes, long *progress) {
    struct thread_info *thread = malloc(sizeof(struct thread_info));

    thread->args = malloc(sizeof(struct args));
    thread->args->finish = finish;
    thread->args->progress = progress;
    thread->args->n_hashes = n_hashes;

    if (0 != pthread_create(&thread->id, NULL, print_progress, thread->args)) {
        printf("Could not create thread\n");
        exit(1);
    }

    return thread;
}

void free_thread(struct thread_info *thread) {
    free(thread->args);
    free(thread);
}

void free_threads(struct thread_info *threads) {
    pthread_mutex_destroy(threads[0].args->mutex_finish);
    pthread_mutex_destroy(threads[0].args->mutex_progress);
    free(threads[0].args->mutex_finish);
    free(threads[0].args->mutex_progress);

    for (int i = 0; i < THREADS; ++i) {
        free(threads[i].args);
    }

    free(threads);
}

int main(int argc, char *argv[]) {
    struct thread_info *calc; // thread for calculations
    struct thread_info *progress; // thread for progress bar
    int *finish = malloc(sizeof(int));
    long *prog = malloc(sizeof(long));

    if (argc < 2) {
        printf("Use: %s string\n", argv[0]);
        exit(0);
    }
    int n_hashes = argc - 1;
    struct solutions *solutions = malloc(sizeof(struct solutions) * n_hashes);
    for (int i = 0; i < n_hashes; ++i) {
        solutions[i].md5 = malloc(sizeof(unsigned char) * MD5_DIGEST_LENGTH);
        solutions[i].pass = malloc((PASS_LEN + 1) * sizeof(char));
        solutions[i].done = 0;
        hex_to_num(argv[i + 1], solutions[i].md5);
    }

    *finish = 0;
    *prog = 0;
    progress = start_thread(finish, n_hashes, prog);
    calc = start_threads(solutions, n_hashes, finish, prog);

    for (int i = 0; i < THREADS; ++i) {
        pthread_join(calc[i].id, NULL);
    }
    pthread_join(progress->id, NULL);

    // print and free solutions 
    for (int i = 0; i < n_hashes; ++i) {
        if (solutions[i].done) {
            printf("%s: %s\n", argv[i + 1], solutions[i].pass);
        } else {
            printf("%s: not found\n", argv[i + 1]);
        }
        free(solutions[i].md5);
        free(solutions[i].pass);
    }

    free(solutions);
    free_thread(progress);
    free_threads(calc);

    free(finish);
    free(prog);

    return 0;
}