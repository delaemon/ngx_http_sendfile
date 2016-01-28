#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <nginx.h>
#include "/usr/include/libmemcached/memcached.h"

static char* ngx_http_sendfile(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static ngx_int_t ngx_http_sendfile_init(ngx_conf_t *cf);
static void *ngx_http_sendfile_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_sendfile_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child);

typedef struct {
    ngx_flag_t enable;
} ngx_http_sendfile_loc_conf_t;

const ngx_command_t ngx_http_sendfile_commands[] = {
    { ngx_string("http_sendfile"),
      NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_FLAG,
      ngx_http_sendfile,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },
    ngx_null_command
};

static ngx_http_module_t ngx_http_sendfile_module_ctx = {
    NULL,                                  /* preconfiguration */
    ngx_http_sendfile_init,                /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    ngx_http_sendfile_create_loc_conf,     /* create location configration */
    ngx_http_sendfile_merge_loc_conf       /* merge location configration */
};

ngx_module_t ngx_http_sendfile_module = {
    NGX_MODULE_V1,

    &ngx_http_sendfile_module_ctx,               // void                 *ctx;
    (ngx_command_t*)ngx_http_sendfile_commands,  // ngx_command_t        *commands;
    NGX_HTTP_MODULE,                             // ngx_uint_t            type;

    NULL,                                        // ngx_int_t           (*init_master)(ngx_log_t *log);

    NULL,                                        // ngx_int_t           (*init_module)(ngx_cycle_t *cycle);

    NULL,                                        // ngx_int_t           (*init_process)(ngx_cycle_t *cycle);
    NULL,                                        // ngx_int_t           (*init_thread)(ngx_cycle_t *cycle);
    NULL,                                        // void                (*exit_thread)(ngx_cycle_t *cycle);
    NULL,                                        // void                (*exit_process)(ngx_cycle_t *cycle);

    NULL,                                        // void                (*exit_master)(ngx_cycle_t *cycle);

    NGX_MODULE_V1_PADDING
};


static ngx_str_t ngx_http_sendfile_root = ngx_string("/files/");
static ngx_int_t ngx_http_sendfile_handler(ngx_http_request_t *r)
{
    ngx_http_sendfile_loc_conf_t *sfcf;
    u_char *p;
    struct memcached_st *mc;
    char *mc_res, *path;
    int len;
    ngx_str_t uri;

    if (!(r->method & (NGX_HTTP_GET|NGX_HTTP_HEAD))) {
        return NGX_DECLINED;
    }
    sfcf = ngx_http_get_module_loc_conf(r, ngx_http_sendfile_module);
    if (!sfcf->enable) {
        return NGX_DECLINED;
    }

    p = &r->uri.data[r->uri.len-1];
    len = 0;
    while (*p >= '0' && *p <= '9') { p--; len++; }
    p++;
    if (len <= 0) return NGX_DECLINED;

    mc = memcached_create();
    memcached_server_add(mc, "127.0.0.1", 11211);
    mc_res = memcached_get(mc, (char*)p, len);
    path = mc_res + 4;

    uri.len = ngx_http_sendfile_root.len + strlen(path);
    uri.data = ngx_pnalloc(r->pool, uri.len);
    if (uri.data == NULL) return NGX_HTTP_INTERNAL_SERVER_ERROR;
    ngx_memcpy(uri.data, ngx_http_sendfile_root.data, ngx_http_sendfile_root.len);
    ngx_memcpy(uri.data + ngx_http_sendfile_root.len, (u_char*)path, strlen(path));

    free(mc_res);
    mc_free(mc);

    //ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0, path);
    return ngx_http_internal_redirect(r, &uri, &r->args);
}


static char* ngx_http_sendfile(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_str_t *value;
    ngx_http_sendfile_loc_conf_t *sfcf = conf;
     
    value = cf->args->elts;
    if (ngx_strcasecmp(value[1].data, (u_char *)"on") == 0) {
        sfcf->enable = 1;
    } else if (ngx_strcasecmp(value[1].data, (u_char *)"off") == 0) {
        sfcf->enable = 0;
    } else {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "\"http_sendfile\" must be either set to \"on\" or \"off\"");
        return NGX_CONF_ERROR;
    }
    return NGX_CONF_OK;
}


static ngx_int_t ngx_http_sendfile_init(ngx_conf_t *cf)
{
    ngx_http_handler_pt       *h;
    ngx_http_core_main_conf_t *cmcf;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_CONTENT_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_http_sendfile_handler;

    return NGX_OK;
}


static void *ngx_http_sendfile_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_sendfile_loc_conf_t *conf;

    conf = ngx_palloc(cf->pool, sizeof(ngx_http_sendfile_loc_conf_t));
    if (conf == NULL) return NULL;
    conf->enable = NGX_CONF_UNSET;

    return conf;
}


static char *ngx_http_sendfile_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_sendfile_loc_conf_t *prev = parent;
    ngx_http_sendfile_loc_conf_t *conf = child;

    ngx_conf_merge_value(conf->enable, prev->enable, 0);

    return NGX_CONF_OK;
}
