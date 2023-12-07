#include "radclient.h"
#include <errno.h>

#define TRIES_LIMIT     5  /*resend tries limit*/
#define EXPIRT_LIMIT    10 /*expire timeout*/
#define RADIUS_PWD_LEN  64

#define DEFAULT_RADIUS_HOST "127.0.0.1"
#define DEFAULT_RADIUS_PORT 1812
#define DEFAULT_SHARED_SECRET "testing123"
#define DEFAULT_AUTH_TYPE PAP

typedef struct auth_radius_proxy_s auth_radius_proxy_t;
typedef struct auth_radius_request_s auth_radius_request_t;

typedef struct radius_request_list_s {
    auth_radius_request_t*              prev;
    auth_radius_request_t*              next;
}radius_request_list_t;


struct auth_radius_proxy_s {
    fr_packet_list_t*                   request_packets;
    radius_request_list_t               requests;
    int                                 sockfd;
};

struct auth_radius_request_s {
    RADIUS_PACKET*                      request;
    RADIUS_PACKET*                      reply;

    char                                password[RADIUS_PWD_LEN];
    time_t                              timestamp;
    time_t                              expire;

    /*the times that we have tried to send it*/
    int8_t                              tries;
    uint8_t                             done;

    radius_request_list_t               node;
    RADIUS_AUTH_TYPE                    auth_type;
};


static auth_radius_proxy_t*
create_auth_radius_proxy() {
    auth_radius_proxy_t* proxy = NULL;

    proxy = (auth_radius_proxy_t*)calloc(1, sizeof(*proxy));
    if (proxy == NULL) {
        fprintf(stderr, "out of memory to create radius proxy\n");
        return NULL;
    }

    proxy->request_packets = fr_packet_list_create(1);
    if (proxy->request_packets == NULL) {
        fprintf(stderr, "out of memory to create packet list\n");

        free(proxy);
        return NULL;
    }

    proxy->sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (proxy->sockfd == -1) {
        fprintf(stderr, "failed to create socket,because %s\n",
                strerror(errno));

        free(proxy);
        fr_packet_list_free(proxy->request_packets);
        return NULL;
    }

    fr_packet_list_socket_add(proxy->request_packets, proxy->sockfd);

    return proxy;
}

static void
destroy_auth_radius_proxy(auth_radius_proxy_t* proxy) {
    fr_packet_list_socket_remove(proxy->request_packets, proxy->sockfd);
    free(proxy);
}

void
radius_request_list_insert_tail(radius_request_list_t* list,
                                auth_radius_request_t* r)
{
    radius_request_list_t* node = NULL;

    node = &r->node;

    if (list->prev == NULL) {
        list->prev = r;
        list->next = r;
    } else {
        list->next->node.next = r;
        node->prev = list->next;
        list->next = r;
    }
}

void
radius_request_list_delete(radius_request_list_t* list,
                           auth_radius_request_t* r)
{
    radius_request_list_t* node = &r->node;

    if (node->prev) {
        node->prev->node.next = node->next;
    }

    if (node->next) {
        node->next->node.prev = node->prev;
    }

    if (node->next == NULL) {
        //node is the tail
        list->next = node->prev;
    }

    if (node->prev == NULL) {
        //node is the head
        list->prev = node->next;
    }

    node->prev = node->next = NULL;
}

typedef void (*walk_fn)(auth_radius_request_t*, void*);

void
radius_request_list_walk(radius_request_list_t* list,
                         walk_fn fn, void* ctx) {
    auth_radius_request_t* r = NULL;

    r = list->prev;
    while (r != NULL) {
        fprintf(stderr, "request: %p\n", r);
        fn(r, ctx);
        r = r->node.next;
    }
}

static auth_radius_request_t*
auth_radius_request_create(auth_radius_proxy_t* proxy,
                           const char* server_host,
                           short server_port,
                           const char* username,
                           const char* password,
                           RADIUS_AUTH_TYPE auth_type)
{
    RADIUS_PACKET* rp = NULL;
    auth_radius_request_t* r = NULL;
    struct sockaddr_in rad_server;
    int port = server_port;

    r = (auth_radius_request_t*)calloc(1, sizeof(*r));
    if (r == NULL) {
        fprintf(stderr, "out of memory to create radius request\n");
        return NULL;
    }

    rp = rad_request_packet_create(username, strlen(username),
                                   password, strlen(password),
                                   auth_type);
    if (rp == NULL) {
        free(r);
        return NULL;
    }

    memset(&rad_server, 0, sizeof(struct sockaddr_in));
    rad_server.sin_family = AF_INET;
    rad_server.sin_addr.s_addr = inet_addr(server_host);
    rad_server.sin_port = htons(server_port);

    memset(&rp->dst_ipaddr, 0, sizeof(rp->dst_ipaddr));
    fr_sockaddr2ipaddr((const struct sockaddr_storage*)&rad_server,
                       sizeof(struct sockaddr_in),
                       &rp->dst_ipaddr, &port);
    rp->dst_port = port & 0xFFFF;
    rp->sockfd = -1;
    rp->src_ipaddr.af = rp->dst_ipaddr.af;

    if (fr_packet_list_id_alloc(proxy->request_packets, rp) == 0) {
        fprintf(stderr, "alloc radius id failed,because : %s\n", fr_strerror());
        rad_free(&rp);
        free(r);
        return NULL;
    }

    if(auth_type == EAPMD5) {
        //set the value of EAP-ID to value of rp->id
        if(rad_set_eap_id(rp) == -1) {
            rad_free(&rp);
            free(r);
            return NULL;
        }
    }

    r->request = rp;
    memcpy(r->password, password, strlen(password));
    r->auth_type = auth_type;

    return r;
}

static void
auth_radius_request_destroy(auth_radius_proxy_t* proxy,
                            auth_radius_request_t* r) {
    if (r->request) {
        fr_packet_list_id_free(proxy->request_packets, r->request);
        rad_free(&r->request);
    }

    if (r->reply) {
        rad_free(&r->reply);
    }

    free(r);
}

static int
auth_radius_request_send(auth_radius_request_t* r,
                         const char* shared_secret) {
    if (r->auth_type == EAPMD5) {
        return rad_send_eap_response(r->request, shared_secret, r->password);
    }

    return rad_send_request(r->request, shared_secret, r->password);
}

static void
auth_radius_request_add(auth_radius_proxy_t* proxy,
                        auth_radius_request_t* r)
{
    radius_request_list_insert_tail(&proxy->requests ,r);
}

static void
auth_radius_request_delete(auth_radius_proxy_t* proxy,
                           auth_radius_request_t* r) {
    radius_request_list_delete(&proxy->requests, r);
}

static void
process_radius_reply(auth_radius_proxy_t* proxy,
                     auth_radius_request_t* r,
                     const char* shared_secret)
{
    if (rad_verify(r->reply, r->request, shared_secret) == -1) {
        rad_free(&r->reply);
        r->reply = NULL;
    } else {
        rad_decode(r->reply, r->request, shared_secret);
        if (r->auth_type == EAPMD5) {
            rad_unmap_eap_types(r->reply);
        }

        fprintf(stderr, "receive response: ");
        debug_reply_packet(r->reply);
    }
}

static void
usage(const char* prog) {
    fprintf(stderr, "Usage: %s [options...]\n"
            "    [-H <host>]    radius server host, default: 127.0.0.1\n"
            "    [-P <port>]    radius server port, default: 1812\n"
            "    [-S <secret>]  radius client shared secret, default: testing123\n"
            "     -u <username> username\n"
            "     -p <password> password\n"
            "    [-a <auth>]    auth type (PAP|CHAP|MSCHAP|MSCHAPV2|EAPMD5), default: PAP\n"
            "    [-d <path>]    dictionary path\n"
            "    [-h]           help\n",
            prog);
}

static void
missing(const char* prog, const char* name) {
    fprintf(stderr, "%s: missing option -- '%s'\n", prog, name);
}

static RADIUS_AUTH_TYPE
parse_auth_type(const char* prog, const char* str) {
    static struct { const char* key; RADIUS_AUTH_TYPE val; } kvs[] = {
        { "PAP"     , PAP      },
        { "CHAP"    , CHAP     },
        { "MSCHAP"  , MSCHAP   },
        { "MSCHAPV2", MSCHAPV2 },
        { "EAPMD5"  , EAPMD5   },
    };
    int i;
    for (i = 0; i < sizeof(kvs)/sizeof(kvs[0]); ++i) {
        if (strcasecmp(str, kvs[i].key) == 0) {
            return kvs[i].val;
        }
    }
    fprintf(stderr, "%s: invalid auth type -- '%s'\n", prog, str);
    usage(prog);
    exit(EXIT_FAILURE);
}

/*
 *Note:
 * we just process one radius request,and it just a example,
 * so we don't think about resend.
 */
int main(int argc, char* argv[]) {
    auth_radius_proxy_t* proxy = NULL;
    auth_radius_request_t* r = NULL;
    fd_set fds;
    struct timeval tv = {5, 0};//5 seconds
    int nfds = 0;

    char* server_host = DEFAULT_RADIUS_HOST;
    short server_port = DEFAULT_RADIUS_PORT;
    char* shared_secret = DEFAULT_SHARED_SECRET;
    char* username = NULL;
    char* password = NULL;
    RADIUS_AUTH_TYPE auth_type = DEFAULT_AUTH_TYPE;
    char* dict_path = NULL;

    if (argc == 1) {
        usage(argv[0]);
        exit(EXIT_FAILURE);
    }

    int opt;
    while ((opt = getopt(argc, argv, "H:P:S:u:p:d:a:h")) != -1) {
        switch (opt) {
        case 'H':
            server_host = optarg;
            break;
        case 'P':
            server_port = atoi(optarg) & 0xFFFF;
            break;
        case 'S':
            shared_secret = optarg;
            break;
        case 'u':
            username = optarg;
            break;
        case 'p':
            password = optarg;
            break;
        case 'd':
            dict_path = optarg;
            break;
        case 'a':
            auth_type = parse_auth_type(argv[0], optarg);
            break;
        case 'h':
            usage(argv[0]);
            exit(EXIT_SUCCESS);
            break;
        default:
            usage(argv[0]);
            exit(EXIT_FAILURE);
        }
    }

    if (!username) {
        missing(argv[0], "username");
        usage(argv[0]);
        exit(EXIT_FAILURE);
    }

    if (!password) {
        missing(argv[0], "password");
        usage(argv[0]);
        exit(EXIT_FAILURE);
    }

    if (dict_init(dict_path, "dictionary") == -1) {
        fprintf(stderr, "failed to initial radius dictionary: %s",
                fr_strerror());
        exit(EXIT_FAILURE);
    }

    proxy = create_auth_radius_proxy();
    if (proxy == NULL) {
        exit(EXIT_FAILURE);
    }

    r = auth_radius_request_create(proxy,
                                   server_host, server_port,
                                   username, password,
                                   auth_type);
    if (r == NULL) {
        exit(EXIT_FAILURE);
    }

    if (auth_radius_request_send(r, shared_secret) == -1) {
        auth_radius_request_destroy(proxy, r);
        exit(EXIT_FAILURE);
    }

    auth_radius_request_add(proxy, r);
    debug_request_packet(r->request);

    while (1) {
        FD_ZERO(&fds);
        FD_SET(r->request->sockfd, &fds);

        tv.tv_sec = 5;
        tv.tv_usec = 0;

        nfds = select(r->request->sockfd + 1, &fds, NULL, NULL, &tv);
        if (nfds == 0) {
            fprintf(stderr, "timed out\n");
        } else if (nfds == -1) {
            if(errno == EINTR) {
                continue;
            } else {
                fprintf(stderr, "error: %s\n", strerror(errno));
            }
        } else {
            r->reply = rad_recv(r->request->sockfd, 0);
            if (r->reply != NULL) {
                process_radius_reply(proxy, r, shared_secret);
                if (r->auth_type == EAPMD5 && r->reply->code == PW_ACCESS_CHALLENGE) {
                    //process EAP-MD5 Access-Challenge,send EAP-MD5 request.
                    rad_process_eap_request(r->request,
                                            r->reply,
                                            shared_secret,
                                            r->password);
                    rad_free(&r->reply);
                    r->reply = NULL;
                } else {
                    auth_radius_request_delete(proxy, r);
                    auth_radius_request_destroy(proxy,r );
                    break;
                }
            }
        }
    }

    destroy_auth_radius_proxy(proxy);

    return EXIT_SUCCESS;
}
