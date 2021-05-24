/*
Copyright Netfoundry, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

https://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef NGX_ZITI_DOWNSTREAM_MODULE_H
#define NGX_ZITI_DOWNSTREAM_MODULE_H


#include <nginx.h>
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


#include <ziti/ziti.h>
#include <uv.h>
#include <ziti/ziti_src.h>
#include <ziti/ziti_log.h>


#ifndef NGX_HTTP_GONE
#define NGX_HTTP_GONE  410
#endif

extern uv_loop_t *uv_thread_loop;

static ngx_str_t ngx_ziti_downstream_thread_pool_name = ngx_string("ziti_downstream");

extern ngx_module_t ngx_ziti_downstream_module;

// typedef struct {
//     ngx_str_t                   name;
//     ngx_str_t                   sv;
//     ngx_http_complex_value_t   *cv;
//     ngx_str_t                  *cmd;
// } ngx_conf_str_t;


// typedef struct {
//     ngx_uint_t                          key;
//     ngx_str_t                           sv;
//     ngx_http_complex_value_t           *cv;
// } ngx_ziti_mixed_t;


// typedef struct {
//     u_char                             *name;
//     uint32_t                            key;
// } ngx_ziti_http_method_t;



typedef enum ZITI_LOC_STATE_tag
{
    ZS_LOC_INIT = 0,
    ZS_LOC_UV_LOOP_STARTED,
    ZS_LOC_ZITI_INIT_STARTED,
    ZS_LOC_ZITI_INIT_COMPLETED,
    ZS_LOC_ZITI_LAST
} ZITI_LOC_STATE;

typedef struct {
    uv_loop_t                          *uv_thread_loop;
    ZITI_LOC_STATE                      state;    
    ngx_pool_t                         *pool;
    /* abs path to ziti identity */
    ngx_str_t                           identity_path;
    /* ziti service name */
    ngx_str_t                           servicename;
    /* endpoint to handle the de-zitified request */
    ngx_str_t                           upstream_dest;
    size_t                              buf_size;
    uv_thread_t                         thread;
    uv_async_t                          async;
    ziti_context                        ztx;
	ngx_thread_pool_t                  *thread_pool;
    size_t                              client_pool_size;
} ngx_ziti_downstream_srv_conf_t;


typedef struct {
    ngx_int_t                           status;
} ngx_ziti_downstream_ctx_t;


typedef struct {
    ngx_http_request_t *r;
    ngx_ziti_downstream_srv_conf_t *zscf;
} ngx_ziti_downstream_uv_run_thread_ctx_t;

typedef struct {
    ngx_http_request_t *r;
    ngx_ziti_downstream_srv_conf_t *zscf;
} ngx_ziti_downstream_await_init_thread_ctx_t;

void ngx_ziti_downstream_on_ziti_init(ziti_context ztx, const ziti_event_t *ev);
void ngx_ziti_downstream_listen_cb(ziti_connection serv, int status);
void ngx_ziti_downstream_on_client(ziti_connection serv, ziti_connection client, int status, ziti_client_ctx *clt_ctx);
ssize_t ngx_ziti_downstream_on_client_data(ziti_connection clt, uint8_t *data, ssize_t len);
void ngx_ziti_downstream_on_client_connect(ziti_connection clt, int status);
void ngx_ziti_downstream_on_client_write(ziti_connection clt, ssize_t status, void *ctx);
int talk_to_upstream(char *response, char *host, int portno, int len, u_int8_t *data);

#endif /* NGX_ZITI_DOWNSTREAM_MODULE_H */
