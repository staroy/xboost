
#ifndef __AUTH_H_INCLUDED__
#define __AUTH_H_INCLUDED__

#ifdef __cplusplus
extern "C" {
#endif

void domain_auth (zsock_t *pipe, void *certs);

#ifdef __cplusplus
}
#endif

#endif
