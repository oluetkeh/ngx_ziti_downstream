
#include <stdio.h> /* printf, sprintf */
#include <stdlib.h> /* exit */
#include <unistd.h> /* read, write, close */
#include <string.h> /* memcpy, memset */
#include <sys/socket.h> /* socket, connect */
#include <netinet/in.h> /* struct sockaddr_in, struct sockaddr */
#include <netdb.h> /* struct hostent, gethostbyname */

#include "ngx_ziti_downstream_module.h"

#ifndef NGX_THREADS
#error ngx_http_ziti_module requires --with-threads
#endif /* NGX_THREADS */

#define RCV_BUFFER_SIZE 10*1024*1024
// #define ZITI_MAX_CHUNK_SIZE 65536
#define ZITI_MAX_CHUNK_SIZE 32000

static ngx_int_t ngx_ziti_downstream_preconfiguration(ngx_conf_t *cf);
static char *ziti_downstream(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

static ngx_int_t ngx_ziti_downstream_handler(ngx_http_request_t *r);
static void *ngx_ziti_downstream_create_srv_conf(ngx_conf_t *cf);
static char *ngx_ziti_downstream_merge_srv_conf(ngx_conf_t *cf, void *parent,
    void *child);
// static ngx_int_t ngx_ziti_downstream(ngx_cycle_t *cycle);


static ngx_command_t  ngx_ziti_downstream_commands[] = {

    { ngx_string("ziti_downstream"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE3,
      ziti_downstream,
      NGX_HTTP_SRV_CONF_OFFSET,
      0,
      NULL },
    
      ngx_null_command
};


static ngx_http_module_t  ngx_ziti_downstream_module_ctx = {
    ngx_ziti_downstream_preconfiguration,        /* preconfiguration */
    NULL,                                  /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    ngx_ziti_downstream_create_srv_conf,   /* create server configuration */
    ngx_ziti_downstream_merge_srv_conf,    /* merge server configuration */

    NULL,                                  /* create location configuration */
    NULL                                   /* merge location configuration */
};


ngx_module_t  ngx_ziti_downstream_module = {
    NGX_MODULE_V1,
    &ngx_ziti_downstream_module_ctx,       /* module context */
    ngx_ziti_downstream_commands,          /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};

static ziti_context ziti;
static const char *ziti_service_name;
uv_loop_t *uv_thread_loop;
static const char *ALL_CONFIG_TYPES[] = {
        "all",
        NULL
};


/**
 * 
 */
static ngx_int_t
ngx_ziti_downstream_preconfiguration(ngx_conf_t *cf)
{
    ngx_thread_pool_t          *tp;

    tp = ngx_thread_pool_add(cf, &ngx_ziti_downstream_thread_pool_name);

    if (tp == NULL) {
        return NGX_ERROR;
    }

    uv_thread_loop = uv_default_loop();
    return NGX_OK;
}

static void *
ngx_ziti_downstream_create_srv_conf(ngx_conf_t *cf)
{
    ngx_ziti_downstream_srv_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_ziti_downstream_srv_conf_t));
    if (conf == NULL) {
        return NGX_CONF_ERROR;
    }
    
    conf->buf_size = NGX_CONF_UNSET_SIZE;
    conf->client_pool_size = NGX_CONF_UNSET_SIZE;

    return conf;
}


static char *
ngx_ziti_downstream_merge_srv_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_ziti_downstream_srv_conf_t *prev = parent;
    ngx_ziti_downstream_srv_conf_t *conf = child;

    ngx_conf_merge_str_value(conf->servicename, prev->servicename, NULL);
    ngx_conf_merge_str_value(conf->identity_path, prev->identity_path, NULL);
    ngx_conf_merge_str_value(conf->upstream_dest, prev->upstream_dest, NULL);

    return NGX_CONF_OK;
}


static void 
nop(uv_async_t *handle, int status) { }


static void 
uv_thread_loop_func(void *data){
    uv_loop_t *thread_loop = (uv_loop_t *) data;

    //Start the loop
    uv_run(thread_loop, UV_RUN_DEFAULT);
}

ngx_int_t
ngx_ziti_downstream_start_uv_loop(ngx_ziti_downstream_srv_conf_t *zscf, ngx_log_t *log)
{
    ngx_int_t                      rc;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, log, 0, "ngx_ziti_downstream_start_uv_loop: entered");
    ZITI_LOG(DEBUG, "--- ngx_ziti_downstream_start_uv_loop: entered");
    zscf->ztx = NGX_CONF_UNSET_PTR;

    // Create the libuv thread loop
    zscf->uv_thread_loop = uv_loop_new();
    uv_async_init(zscf->uv_thread_loop, &zscf->async, (uv_async_cb)nop);
    uv_thread_create(&zscf->thread, (uv_thread_cb)uv_thread_loop_func, zscf->uv_thread_loop);

    ziti_options *opts = ngx_calloc(sizeof(ziti_options), log);

    opts->config = (char*)zscf->identity_path.data;
    opts->events = ZitiContextEvent;
    opts->event_cb = ngx_ziti_downstream_on_ziti_init;
    opts->refresh_interval = 60;
    opts->router_keepalive = 10;
    opts->app_ctx = zscf;
    opts->config_types = ALL_CONFIG_TYPES;
    opts->metrics_type = INSTANT;

    rc = ziti_init_opts(opts, zscf->uv_thread_loop);

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, log, 0, "ziti_init_opts returned %d", rc);
    return NGX_OK;
}


static char *
ziti_downstream(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_ziti_downstream_srv_conf_t   *zscf = conf;
    ngx_str_t                  *value = cf->args->elts;
    // ngx_uint_t                  nelts = cf->args->nelts;

    ngx_log_debug0(NGX_LOG_DEBUG, cf->log, 0, "ziti_downstream: entered");
    ZITI_LOG(DEBUG, "--- ziti_downstream: entered");
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, cf->log, 0, "elts: %s", value);
    
    zscf->pool = ngx_create_pool(NGX_DEFAULT_POOL_SIZE, cf->log);
    if (zscf->pool == NULL) {
        return NGX_CONF_ERROR;
    }

    ngx_str_set(&zscf->servicename, strdup((char*)value[1].data));
    ziti_service_name=(char *)zscf->servicename.data;
    ngx_str_set(&zscf->identity_path, strdup((char*)value[2].data));
    ngx_str_set(&zscf->upstream_dest, strdup((char*)value[3].data));

    ngx_ziti_downstream_start_uv_loop(zscf, cf->log);
    return NGX_CONF_OK;
}

void ngx_ziti_downstream_on_ziti_init(ziti_context ztx, const ziti_event_t *ev) {
    ZITI_LOG(DEBUG, "--- ngx_ziti_downstream_on_ziti_init: entered");
    ziti = ztx;
    ziti_connection conn;
    ziti_conn_init(ziti, &conn, NULL);
    ziti_listen_opts listen_opts = {
        .bind_using_edge_identity = false,
        .terminator_precedence = PRECEDENCE_REQUIRED,
        .terminator_cost = 10,
    };
    ziti_listen_with_options(conn, ziti_service_name, &listen_opts, ngx_ziti_downstream_listen_cb, ngx_ziti_downstream_on_client);
}

void ngx_ziti_downstream_listen_cb(ziti_connection serv, int status) {
    ZITI_LOG(DEBUG, "--- ngx_ziti_downstream_listen_cb: entered");
    if (status == ZITI_OK) {
        ZITI_LOG(DEBUG, "Ngx ziti downstream module waiting for client data! %d(%s)", status, ziti_errorstr(status));
    }
    else {
        ZITI_LOG(DEBUG, "ERROR Ngx ziti downstream module could not be started: %d(%s)", status, ziti_errorstr(status));
        ziti_close(serv, NULL);
    }
}

void ngx_ziti_downstream_on_client(ziti_connection serv, ziti_connection client, int status, ziti_client_ctx *clt_ctx) {
    // ZITI_LOG(DEBUG, "--- ngx_ziti_downstream_on_client");
    if (status == ZITI_OK) {
        const char *source_identity = clt_ctx->caller_id;
        if (source_identity != NULL) {
            ZITI_LOG(DEBUG, "incoming connection from '%s'", source_identity);
        }
        else {
            ZITI_LOG(DEBUG, "incoming connection from unidentified client");
        }
        if (clt_ctx->app_data != NULL) {
            ZITI_LOG(DEBUG, "got app data: %d bytes", (int) clt_ctx->app_data_sz);
            ZITI_LOG(TRACE, "got app data:\n'%.*s'", (int) clt_ctx->app_data_sz, clt_ctx->app_data);
        }
        ziti_accept(client, ngx_ziti_downstream_on_client_connect, ngx_ziti_downstream_on_client_data);
    } else {
        ZITI_LOG(DEBUG, "failed to accept client: %s(%d)", ziti_errorstr(status), status);
    }
}

void ngx_ziti_downstream_on_client_connect(ziti_connection clt, int status) {
    ZITI_LOG(DEBUG, "--- ngx_ziti_downstream_on_client_connect");
    if (status == ZITI_OK) {
        // char *msg = "Hello from ngx_ziti_downstream!\n";
        // ziti_write(clt, (u_int8_t *) msg, strlen(msg), ngx_ziti_downstream_on_client_write, NULL);
    }
}

ssize_t ngx_ziti_downstream_on_client_data(ziti_connection clt, uint8_t *data, ssize_t len) {
    // ZITI_LOG(DEBUG, "--- ngx_ziti_downstream_on_client_data\n");

    if (len > 0) {
        ZITI_LOG(DEBUG, "client sent %d bytes", (int) len);
        ZITI_LOG(TRACE, "client sent these %d bytes:\n%.*s", (int) len, (int) len, data);
        
        uv_work_baton_t *req = malloc(sizeof(uv_work_baton_t));
        req->clt = clt;
        req->upstream_server_name="odoo.bomk";
        req->upstream_port=8069;
        req->data = data;
        req->len = len;
        uv_work_t *work = malloc(sizeof(uv_work_t));
        work->data = (void *) req;

        uv_queue_work(uv_thread_loop, work, process_upstream, respond_to_client);
        ZITI_LOG(DEBUG, "request dispatched via uv_queue_work to function process_upstream.");
    }
    else if (len == ZITI_EOF) {
        ZITI_LOG(DEBUG, "client disconnected");
        ziti_close(clt, NULL);
    }
    else {
        ZITI_LOG(DEBUG, "error: %zd(%s)", len, ziti_errorstr(len));
    }
    return len;
}

void process_upstream(uv_work_t *work){
    uv_work_baton_t *req = work->data;
    // forward request to upstream server
    char *reply = malloc(RCV_BUFFER_SIZE);
    memset(reply,0,RCV_BUFFER_SIZE);
    int reply_len = talk_to_upstream(reply, req->upstream_server_name, req->upstream_port, req->len, req->data);
    req->reply = reply;
    req->reply_len = reply_len;
    ZITI_LOG(DEBUG, "finished upstream communication, got %d bytes", reply_len);
}

void respond_to_client(uv_work_t *work, int status){
    ZITI_LOG(DEBUG, "status code after upstream processing: %d", status);

    uv_work_baton_t *res = work->data;
    int reply_len = res->reply_len;
    char *reply = res->reply;
    /* send the reply via ziti */
    int sent = 0;
    int ziti_chunk_len = ZITI_MAX_CHUNK_SIZE; 
    if (reply_len - sent < ziti_chunk_len){
            ziti_chunk_len = reply_len - sent;
        } 
    do {
        char *ziti_chunk = malloc(ziti_chunk_len+1);
        strncpy(ziti_chunk, reply+sent, ziti_chunk_len);
        ZITI_LOG(TRACE, "ziti_chunk to write %d bytes:\n%.*s", ziti_chunk_len, ziti_chunk_len, ziti_chunk);
        int rc = ziti_write(res->clt, (uint8_t *) ziti_chunk, ziti_chunk_len, ngx_ziti_downstream_on_client_write, ziti_chunk);
        sent+=ziti_chunk_len;
        ZITI_LOG(DEBUG, "ziti_write return code after writing %d of %d bytes: %d", sent, reply_len, rc);
        if (reply_len - sent < ziti_chunk_len){
            ziti_chunk_len = reply_len - sent;
        }
    } while (sent < reply_len);
    free(reply);  
    free(res);
    free(work);
}

void ngx_ziti_downstream_on_client_write(ziti_connection clt, ssize_t status, void *ctx) {
    ZITI_LOG(DEBUG, "--- ngx_ziti_downstream_on_client_write status: %d", (int) status);
    free(ctx);
}


int talk_to_upstream(char *response, char *host, int portno, int len, u_int8_t *data)
{
    struct hostent *server;
    struct sockaddr_in serv_addr;
    int sockfd, bytes, sent, received, total;

    /* create the socket */
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        ZITI_LOG(ERROR, "ngx_ziti_downstream: error from upstream server: ERROR opening socket. %d", sockfd);
        return 0;
    }

    /* lookup the ip address */
    server = gethostbyname(host);
    if (sockfd < 0) {
        ZITI_LOG(ERROR, "ngx_ziti_downstream: error from upstream server: ERROR, no such host. %d", sockfd);
        return 0;
    }

    /* fill in the structure */
    memset(&serv_addr,0,sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(portno);
    memcpy(&serv_addr.sin_addr.s_addr,server->h_addr,server->h_length);

    /* connect the socket */
    int rc = connect(sockfd,(struct sockaddr *)&serv_addr,sizeof(serv_addr));
    if (rc < 0){
        ZITI_LOG(ERROR, "ngx_ziti_downstream: error from upstream server: ERROR connecting. %d", rc);
        return 0;
    }

    /* send the request */
    total = strlen((char *)data);
    sent = 0;
    do {
        bytes = write(sockfd,data+sent,total-sent);
        if (bytes < 0) {
            ZITI_LOG(ERROR, "ngx_ziti_downstream: error from upstream server: ERROR writing message to socket. %d", bytes);
            return 0;
        }
        if (bytes == 0)
            break;
        sent+=bytes;
    } while (sent < total);

    ZITI_LOG(DEBUG, "ngx_ziti_downstream: request sent upstream. %d bytes", sent);

    /* receive the response */
    total = RCV_BUFFER_SIZE-1;
    received = 0;
    do {
        bytes = read(sockfd,response+received,total-received);
        if (bytes < 0){
            ZITI_LOG(ERROR, "ngx_ziti_downstream: error from upstream server: ERROR reading response from socket. %d", bytes);
            return 0;
        }
        if (bytes == 0)
            break;
        received+=bytes;
    } while (received < total);

    if (received == total) {
        ZITI_LOG(ERROR, "ngx_ziti_downstream: error from upstream server: ERROR: more bytes returned than buffer size. %d", bytes);
        return 0;
    }
    ZITI_LOG(DEBUG, "ngx_ziti_downstream: response received from upstream. %d bytes", received);
    ZITI_LOG(TRACE, "response from upstream server %d bytes:\n%.*s", received, received, response);

    close(sockfd);
    return received;
}
