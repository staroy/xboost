#include "certs.h"

certs_t *
certs_new ()
{
    certs_t *self = (certs_t *) zmalloc (sizeof (certs_t));
    assert (self);

    self->certs = zhashx_new ();
    assert (self->certs);
    zhashx_set_destructor (self->certs, (czmq_destructor *) zcert_destroy);

    return self;
}

void
certs_destroy (certs_t **self_p)
{
    assert (self_p);
    if (*self_p) {
        certs_t *self = *self_p;
        zhashx_destroy (&self->certs);

        freen (self);
        *self_p = NULL;
    }
}

zcert_t *
certs_lookup (certs_t *self, const char *domain, const char *public_key)
{
    char tmp[512]; strcpy(tmp, domain); strcat(tmp, public_key);
    return (zcert_t *) zhashx_lookup (self->certs, tmp);
}

void
certs_insert (certs_t *self, const char *domain, zcert_t **cert_p)
{
    char tmp[512]; strcpy(tmp, domain); strcat(tmp, zcert_public_txt (*cert_p));
    int rc = zhashx_insert (self->certs, tmp, *cert_p);
    assert (rc == 0);
    *cert_p = NULL;             //  We own this now
}

void
certs_delete (certs_t *self, const char *domain, const char *public_key)
{
    char tmp[512]; strcpy(tmp, domain); strcat(tmp, public_key);
    zhashx_delete (self->certs, tmp);
}

void
certs_empty (certs_t *self)
{
    zhashx_purge (self->certs);
}

zlistx_t *
certs_certs (certs_t *self)
{
    zlistx_t *certs = zhashx_values(self->certs);
    zlistx_set_destructor (certs, NULL);
    return certs;
}

void
certs_print (certs_t *self)
{
    zcert_t *cert = (zcert_t *) zhashx_first (self->certs);
    while (cert) {
        zcert_print (cert);
        cert = (zcert_t *) zhashx_next (self->certs);
    }
}

void *
certs_state (certs_t *self)
{
    assert (self);
    return self->state;
}

