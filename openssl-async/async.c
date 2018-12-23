#ifdef _WIN32
# include <windows.h>
#endif
#include <stdio.h>
#include <unistd.h>
#include <openssl/async.h>
#include <openssl/crypto.h>
#include <sys/eventfd.h>
#include <sys/time.h>


void cleanup(ASYNC_WAIT_CTX *ctx, const void *key, OSSL_ASYNC_FD r, void *vw)
{
    close(r);
}

int jobfunc(void *arg)
{
    ASYNC_JOB *currjob;
    unsigned long data = 1;

    int efd = eventfd(0,0);

    currjob = ASYNC_get_current_job();
    if (currjob == NULL) {
       return 0;
    }

    ASYNC_WAIT_CTX_set_wait_fd(ASYNC_get_wait_ctx(currjob), NULL,
                               efd, NULL, cleanup);

    write(efd, &data, sizeof(data));
    ASYNC_pause_job();
    read(efd, &data, sizeof(data));
    return 1;
}


void  async_job(ASYNC_WAIT_CTX *ctx)
{
    ASYNC_JOB *job = NULL;
    int ret;
    unsigned char msg[13] = "Hello world!";

    int *add_fds = NULL;
    int *del_fds = NULL;
    size_t        num_add_fds = 0;
    size_t        num_del_fds = 0;
    int a[20];
    int b[20];

     for (;;) {
        switch(ASYNC_start_job(&job, ctx, &ret, jobfunc, msg, sizeof(msg))) {
        case ASYNC_ERR:
        case ASYNC_NO_JOBS:
                return;
        case ASYNC_PAUSE:
                break;
        case ASYNC_FINISH:
                return;
        }

        ASYNC_WAIT_CTX_get_changed_fds(ctx, NULL, &num_add_fds,NULL, &num_del_fds);
       
        if(num_add_fds) {
        //    add_fds = malloc(num_add_fds * sizeof(int));   
            add_fds = a;
        }

        if(num_del_fds) {
        //    del_fds = malloc(num_del_fds * sizeof(int));   
            del_fds = b;
        }

        ASYNC_WAIT_CTX_get_changed_fds(ctx, add_fds, &num_add_fds, del_fds, &num_del_fds);
/*
        if(add_fds) {
            free(add_fds);
        }

        if(del_fds) {
            free(del_fds);
        }
*/
    }
}

int main(int argc, char **argv)
{
    ASYNC_WAIT_CTX *ctx = NULL;
    int i,j;
    int job_num = 0;
    unsigned long ms, rps, num;
    struct timeval start,end;

    if(argc != 3) {
        printf("usage:\n\t%s loop-num job-num\n", argv[0]);
        return 1;
    }

    num = atoi(argv[1]);
    job_num = atoi(argv[2]);

    gettimeofday(&start, NULL);
    for (i = 0; i < num; i++) {
        ctx = ASYNC_WAIT_CTX_new();
        if (ctx == NULL) {
            abort();
        }

        for(j = 0; j < job_num; j++) {
            async_job(ctx);
        }

        ASYNC_WAIT_CTX_free(ctx);
    }
    gettimeofday(&end, NULL);
    ms = ((end.tv_sec * 1000 + end.tv_usec/1000) - (start.tv_sec * 1000 + start.tv_usec/1000));
    
    rps = (num*1000)/ms;

    printf("ms %lu num %lu rps %lu\n",ms, num, rps);


    return 0;
}
