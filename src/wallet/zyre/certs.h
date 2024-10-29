#include "czmq.h"

#ifndef __CERTS_H_INCLUDED__
#define __CERTS_H_INCLUDED__

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    void *state;
    zhashx_t *certs;
} certs_t;

certs_t *
    certs_new ();

void
    certs_destroy (certs_t **self_p);

zcert_t *
    certs_lookup (certs_t *self, const char *domain, const char *public_key);

void
    certs_insert (certs_t *self, const char *domain, zcert_t **cert_p);

void
    certs_delete (certs_t *self, const char *domain, const char *public_key);

void
    certs_print (certs_t *self);

void *
    certs_state (certs_t *self);

#ifdef __cplusplus
}
#endif

#endif
