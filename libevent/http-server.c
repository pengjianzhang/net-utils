#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <event2/event.h>
#include <event2/http.h>
#include <event2/buffer.h>

const char * file_1k = "00000000000000000000000000000000000000000000000\n"
"00000000000000000000000000000000000000000000000\n"
"00000000000000000000000000000000000000000000000\n"
"00000000000000000000000000000000000000000000000\n"
"00000000000000000000000000000000000000000000000\n"
"00000000000000000000000000000000000000000000000\n"
"00000000000000000000000000000000000000000000000\n"
"00000000000000000000000000000000000000000000000\n"
"00000000000000000000000000000000000000000000000\n"
"00000000000000000000000000000000000000000000000\n"
"00000000000000000000000000000000000000000000000\n"
"00000000000000000000000000000000000000000000000\n"
"00000000000000000000000000000000000000000000000\n"
"00000000000000000000000000000000000000000000000\n"
"00000000000000000000000000000000000000000000000\n"
"00000000000000000000000000000000000000000000000\n"
"00000000000000000000000000000000000000000000000\n"
"00000000000000000000000000000000000000000000000\n"
"00000000000000000000000000000000000000000000000\n"
"00000000000000000000000000000000000000000000000\n"
"00000000000000000000000000000000000000000000000\n"
"000000000000000\n";

static void zero_cb(struct evhttp_request *req, void *arg)
{
	evhttp_send_reply(req, 200, "OK", NULL);
}

static void notfound_cb(struct evhttp_request *req, void *arg)
{
    evhttp_send_error(req, HTTP_NOTFOUND, NULL);
}

static void file_1k_cb(struct evhttp_request *req, void *arg)
{
	struct evbuffer *evb = NULL;

	if (evhttp_request_get_command(req) != EVHTTP_REQ_GET) {
	    evhttp_send_error(req, HTTP_NOTFOUND, NULL);
        return;
	}

	evb = evbuffer_new();
    evbuffer_add_printf(evb, file_1k);
    evhttp_add_header(evhttp_request_get_output_headers(req), "Content-Type", "text/html");
	evhttp_send_reply(req, 200, "OK", evb);
	evbuffer_free(evb);
}


static void default_cb(struct evhttp_request *req, void *arg)
{
	struct evbuffer *evb = NULL;

	if (evhttp_request_get_command(req) != EVHTTP_REQ_GET) {
	    evhttp_send_error(req, HTTP_NOTFOUND, NULL);
        return;
	}

	evb = evbuffer_new();
    evbuffer_add_printf(evb, "hi, libevent\n");
    evhttp_add_header(evhttp_request_get_output_headers(req), "Content-Type", "text/html");
	evhttp_send_reply(req, 200, "OK", evb);
	evbuffer_free(evb);
}

int g_exit = 0;
static void do_term(int sig, short events, void *arg)
{
	struct event_base *base = arg;
    g_exit = 1;
}

int main(int argc, char **argv)
{
	struct event_base *base = NULL;
	struct evhttp *http = NULL;
	struct event *term = NULL;
	int ret = 0;
    struct timeval tval;

    tval.tv_sec = 0;
    tval.tv_usec = 100 * 1000;

	if (signal(SIGPIPE, SIG_IGN) == SIG_ERR) {
		ret = 1;
		goto err;
	}

	base = event_base_new();
	if (!base) {
        goto err;
	}

	http = evhttp_new(base);
	if (!http) {
        goto err;
	}

	evhttp_set_cb(http, "/zero", zero_cb, NULL);
	evhttp_set_cb(http, "/404",  notfound_cb, NULL);
	evhttp_set_cb(http, "/file/1k",  file_1k_cb, NULL);
	evhttp_set_gencb(http, default_cb, NULL);
    if (evhttp_bind_socket(http, "0.0.0.0", 8000) != 0) {
        goto err;
    }

	term = evsignal_new(base, SIGINT, do_term, base);
	if (!term) {
		goto err;
    }

	if (event_add(term, NULL)) {
		goto err;
    }

    while (1) {
        event_base_loopexit(base, &tval);
	    event_base_dispatch(base);
        if (g_exit) {
            printf("Exit\n");
            break;
        }
    }

err:
	if (http) {
		evhttp_free(http);
    }

	if (term) {
		event_free(term);
    }

	if (base) {
		event_base_free(base);
    }

    return 0;
}
