#include "czmq.h"
#include "certs.h"

#define ZAP_ENDPOINT  "inproc://zeromq.zap.01"

//  --------------------------------------------------------------------------
//  The self_t structure holds the state for one actor instance

typedef struct {
    zsock_t *pipe;              //  Actor command pipe
    zsock_t *handler;           //  ZAP handler socket
    zhashx_t *allowlist;        //  Allowed addresses
    zhashx_t *blocklist;        //  Blocked addresses
    zhashx_t *passwords;        //  PLAIN passwords, if loaded
    zpoller_t *poller;          //  Socket poller
    certs_t *certs;     //  CURVE certificate store, if loaded
    bool allow_any;             //  CURVE allows arbitrary clients
    bool terminated;            //  Did caller ask us to quit?
    bool verbose;               //  Verbose logging enabled?
} self_t;

static void
s_self_destroy (self_t **self_p)
{
    assert (self_p);
    if (*self_p) {
        self_t *self = *self_p;
        zhashx_destroy (&self->passwords);
        zhashx_destroy (&self->allowlist);
        zhashx_destroy (&self->blocklist);
        //certs_destroy (&self->certs);
        zpoller_destroy (&self->poller);
        if (self->handler) {
            zsock_unbind (self->handler, ZAP_ENDPOINT);
            zsock_destroy (&self->handler);
        }
        freen (self);
        *self_p = NULL;
    }
}

static self_t *
s_self_new (zsock_t *pipe, certs_t *certs)
{
    self_t *self = (self_t *) zmalloc (sizeof (self_t));
    assert (self);
    if (certs) {
        self->certs = certs;
        self->allow_any = false;
    }
    self->pipe = pipe;
    self->allowlist = zhashx_new ();
    assert (self->allowlist);
    self->blocklist = zhashx_new ();

    //  Create ZAP handler and get ready for requests
    assert (self->blocklist);
    self->handler = zsock_new (ZMQ_REP);
    assert (self->handler);
    int rc = zsock_bind (self->handler, ZAP_ENDPOINT);
    assert (rc == 0);
    self->poller = zpoller_new (self->pipe, self->handler, NULL);
    assert (self->poller);

    return self;
}


//  --------------------------------------------------------------------------
//  Handle a command from calling application

static int
s_self_handle_pipe (self_t *self)
{
    //  Get the whole message off the pipe in one go
    zmsg_t *request = zmsg_recv (self->pipe);
    if (!request)
        return -1;                  //  Interrupted

    char *command = zmsg_popstr (request);
    if (self->verbose)
        zsys_info ("zauth: API command=%s", command);

    if (streq (command, "ALLOW")) {
        char *address = zmsg_popstr (request);
        while (address) {
            if (self->verbose)
                zsys_info ("zauth: - allowlisting ipaddress=%s", address);
            zhashx_insert (self->allowlist, address, (char *)"OK");
            zstr_free (&address);
            address = zmsg_popstr (request);
        }
        zsock_signal (self->pipe, 0);
    }
    else
    if (streq (command, "DENY")) {
        char *address = zmsg_popstr (request);
        while (address) {
            if (self->verbose)
                zsys_info ("zauth: - blocking ipaddress=%s", address);
            zhashx_insert (self->blocklist, address, (char *)"OK");
            zstr_free (&address);
            address = zmsg_popstr (request);
        }
        zsock_signal (self->pipe, 0);
    }
    else
    if (streq (command, "PLAIN")) {
        //  Get password file and load into zhash table
        //  If the file doesn't exist we'll get an empty table
        char *filename = zmsg_popstr (request);
        zhashx_destroy (&self->passwords);
        self->passwords = zhashx_new ();
        if (zhashx_load (self->passwords, filename) && self->verbose)
            zsys_info ("zauth: could not load file=%s", filename);
        zstr_free (&filename);
        zsock_signal (self->pipe, 0);
    }
    else
    if (streq (command, "CURVE")) {
        //  If location is CURVE_ALLOW_ANY, allow all clients. Otherwise
        //  treat location as a directory that holds the certificates.
        char *location = zmsg_popstr (request);
        if (streq (location, CURVE_ALLOW_ANY))
            self->allow_any = true;
        else {
            certs_destroy (&self->certs);
            // FIXME: what if this fails?
            self->certs = certs_new ();
            self->allow_any = false;
        }
        zstr_free (&location);
        zsock_signal (self->pipe, 0);
    }
    else
    if (streq (command, "GSSAPI"))
        //  GSSAPI authentication is not yet implemented here
        zsock_signal (self->pipe, 0);
    else
    if (streq (command, "VERBOSE")) {
        self->verbose = true;
        zsock_signal (self->pipe, 0);
    }
    else
    if (streq (command, "$TERM"))
        self->terminated = true;
    else {
        zsys_error ("zauth: - invalid command: %s", command);
        assert (false);
    }
    zstr_free (&command);
    zmsg_destroy (&request);
    return 0;
}


//  --------------------------------------------------------------------------
//  A small class for working with ZAP requests and replies.
//  Used internally in zauth to simplify working with RFC 27 messages.

//  Structure of a ZAP request

typedef struct {
    zsock_t *handler;           //  Socket we're talking to
    bool verbose;               //  Log ZAP requests and replies?
    char *version;              //  Version number, must be "1.0"
    char *sequence;             //  Sequence number of request
    char *domain;               //  Server socket domain
    char *address;              //  Client IP address
    char *identity;             //  Server socket idenntity
    char *mechanism;            //  Security mechansim
    char *username;             //  PLAIN user name
    char *password;             //  PLAIN password, in clear text
    char *client_key;           //  CURVE client public key in ASCII
    char *principal;            //  GSSAPI client principal
    char *user_id;              //  User-Id to return in the ZAP Response
} zap_request_t;


static void
s_zap_request_destroy (zap_request_t **self_p)
{
    assert (self_p);
    if (*self_p) {
        zap_request_t *self = *self_p;
        freen (self->version);
        freen (self->sequence);
        freen (self->domain);
        freen (self->address);
        freen (self->identity);
        freen (self->mechanism);
        freen (self->username);
        freen (self->password);
        freen (self->client_key);
        freen (self->principal);
        // self->user_id is a pointer to one of the above fields
        freen (self);
        *self_p = NULL;
    }
}

//  Receive a valid ZAP request from the handler socket
//  If the request was not valid, returns NULL.

static zap_request_t *
s_zap_request_new (zsock_t *handler, bool verbose)
{
    zap_request_t *self = (zap_request_t *) zmalloc (sizeof (zap_request_t));
    if (!self)
        return NULL;

    //  Store handler socket so we can send a reply easily
    self->handler = handler;
    self->verbose = verbose;
    zmsg_t *request = zmsg_recv (handler);
    if (!request) { // interrupted
        s_zap_request_destroy (&self);
        return NULL;
    }

    //  Get all standard frames off the handler socket
    self->version = zmsg_popstr (request);
    self->sequence = zmsg_popstr (request);
    self->domain = zmsg_popstr (request);
    self->address = zmsg_popstr (request);
    self->identity = zmsg_popstr (request);
    self->mechanism = zmsg_popstr (request);

    //  If the version is wrong, we're linked with a bogus libzmq, so die
    assert (streq (self->version, "1.0"));

    //  Get mechanism-specific frames
    if (streq (self->mechanism, "PLAIN")) {
        self->username = zmsg_popstr (request);
        self->password = zmsg_popstr (request);
    }
    else
    if (streq (self->mechanism, "CURVE")) {
        zframe_t *frame = zmsg_pop (request);
        assert (zframe_size (frame) == 32);
        self->client_key = (char *) zmalloc (41);
#if (ZMQ_VERSION_MAJOR == 4)
        zmq_z85_encode (self->client_key, zframe_data (frame), 32);
#endif
        zframe_destroy (&frame);
    }
    else
    if (streq (self->mechanism, "GSSAPI"))
        self->principal = zmsg_popstr (request);

    if (self->verbose)
        zsys_info ("zauth: ZAP request mechanism=%s ipaddress=%s",
                   self->mechanism, self->address);
    zmsg_destroy (&request);
    return self;
}

//  Send a ZAP reply to the handler socket

static int
s_zap_request_reply (zap_request_t *self, char *status_code, char *status_text, unsigned char *metadata, size_t metasize)
{
    if (self->verbose)
        zsys_info ("zauth: - ZAP reply status_code=%s status_text=%s",
                   status_code, status_text);

    zmsg_t *msg = zmsg_new ();
    int rc = zmsg_addstr(msg, "1.0");
    assert (rc == 0);
    rc = zmsg_addstr(msg, self->sequence);
    assert (rc == 0);
    rc = zmsg_addstr(msg, status_code);
    assert (rc == 0);
    rc = zmsg_addstr(msg, status_text);
    assert (rc == 0);
    rc = zmsg_addstr(msg, self->user_id ? self->user_id : "");
    assert (rc == 0);
    rc = zmsg_addmem(msg, metadata, metasize);
    assert (rc == 0);
    rc = zmsg_send(&msg, self->handler);
    assert (rc == 0);

    return 0;
}


//  --------------------------------------------------------------------------
//  Handle an authentication request from libzmq core

//  Helper for s_add_property
//  THIS IS A COPY OF zmq::put_uint32 (<zmq>/src/wire.hpp)

static void
s_put_uint32 (unsigned char *buffer_, uint32_t value)
{
    buffer_ [0] = (unsigned char) (((value) >> 24) & 0xff);
    buffer_ [1] = (unsigned char) (((value) >> 16) & 0xff);
    buffer_ [2] = (unsigned char) (((value) >> 8) & 0xff);
    buffer_ [3] = (unsigned char) (value & 0xff);
}

//  Add metadata property to ptr
//  THIS IS AN ADAPTATION OF zmq::mechanism_t::add_property (<zmq>/src/mechanism.cpp)

static size_t
s_add_property (unsigned char *ptr, const char *name, const void *value, size_t value_len)
{
    const size_t name_len = strlen (name);
    assert (name_len <= 255);
    *ptr++ = (unsigned char) name_len;
    memcpy (ptr, name, name_len);
    ptr += name_len;
    assert (value_len <= 0x7FFFFFFF);
    s_put_uint32 (ptr, (uint32_t) value_len);
    ptr += 4;
    memcpy (ptr, value, value_len);

    return 1 + name_len + 4 + value_len;
}

static bool
s_authenticate_plain (self_t *self, zap_request_t *request)
{
    if (self->passwords) {
        zhashx_refresh (self->passwords);
        char *password = (char *) zhashx_lookup (self->passwords, request->username);
        if (password && streq (password, request->password)) {
            if (self->verbose)
                zsys_info ("zauth: - allowed (PLAIN) username=%s password=%s",
                           request->username, request->password);
            request->user_id = request->username;
            return true;
        }
        else {
            if (self->verbose)
                zsys_info ("zauth: - denied (PLAIN) username=%s password=%s",
                           request->username, request->password);
            return false;
        }
    }
    else {
        if (self->verbose)
            zsys_info ("zauth: - denied (PLAIN) no password file defined");
        return false;
    }
}


static bool
s_authenticate_curve (self_t *self, zap_request_t *request, unsigned char **metadata)
{
    if (self->allow_any) {
        if (self->verbose)
            zsys_info ("zauth: - allowed (CURVE allow any client)");
        return true;
    }
    else
    if (self->certs) {
        zcert_t *cert = certs_lookup (self->certs, request->domain, request->client_key);
        if (cert != NULL) {
            zlist_t *meta_k = zcert_meta_keys (cert);
            while (true) {
                void *key = zlist_next (meta_k);
                if (key == NULL) {
                    break;
                }

                const char *val = zcert_meta(cert, (const char *) key);
                if (val == NULL) {
                    break;
                }

                *metadata += s_add_property(*metadata, (const char *) key, val, strlen (val));
            }
            zlist_destroy (&meta_k);

            if (self->verbose)
                zsys_info ("zauth: - allowed (CURVE) client_key=%s", request->client_key);
            request->user_id = request->client_key;
            return true;
        }
    }

    if (self->verbose)
        zsys_info ("zauth: - denied (CURVE) client_key=%s", request->client_key);
    return false;
}

static bool
s_authenticate_gssapi (self_t *self, zap_request_t *request)
{
    if (self->verbose)
        zsys_info ("zauth: - allowed (GSSAPI) principal=%s identity=%s",
                   request->principal, request->identity);
    request->user_id = request->principal;
    return true;
}

//  TODO: allow regular expressions in addresses
static int
s_self_authenticate (self_t *self)
{
    zap_request_t *request = s_zap_request_new (self->handler, self->verbose);
    if (!request)
        return 0;           //  Interrupted, no request to process

    //  Is address explicitly allowed or blocked?
    bool allowed = false;
    bool denied = false;

    //  Curve certificate metadata
    unsigned char * const metabuf = (unsigned char *) malloc (512);
    assert (metabuf != NULL);
    unsigned char *metadata = metabuf;

    if (zhashx_size (self->allowlist)) {
        if (zhashx_lookup (self->allowlist, request->address)) {
            allowed = true;
            if (self->verbose)
                zsys_info ("zauth: - passed (allowed list) address=%s", request->address);
        }
        else {
            denied = true;
            if (self->verbose)
                zsys_info ("zauth: - denied (not in allowed list) address=%s", request->address);
        }
    }
    else
    if (zhashx_size (self->blocklist)) {
        if (zhashx_lookup (self->blocklist, request->address)) {
            denied = true;
            if (self->verbose)
                zsys_info ("zauth: - denied (blocked list) address=%s", request->address);
        }
        else {
            allowed = true;
            if (self->verbose)
                zsys_info ("zauth: - passed (not in blocked list) address=%s", request->address);
        }
    }
    //  Mechanism-specific checks
    if (!denied) {
        if (streq (request->mechanism, "NULL") && !allowed) {
            //  For NULL, we allow if the address wasn't blocked
            if (self->verbose)
                zsys_info ("zauth: - allowed (NULL)");
            allowed = true;
        }
        else
        if (streq (request->mechanism, "PLAIN"))
            //  For PLAIN, even a allowlisted address must authenticate
            allowed = s_authenticate_plain (self, request);
        else
        if (streq (request->mechanism, "CURVE"))
            //  For CURVE, even a allowlisted address must authenticate
            allowed = s_authenticate_curve (self, request, &metadata);
        else
        if (streq (request->mechanism, "GSSAPI"))
            //  For GSSAPI, even a allowlisted address must authenticate
            allowed = s_authenticate_gssapi (self, request);
    }
    if (allowed) {
        size_t metasize = metadata - metabuf;
        s_zap_request_reply (request, (char *)"200", (char *)"OK", metabuf, metasize);
    } else
        s_zap_request_reply (request, (char *)"400", (char *)"No access", (unsigned char *) "", 0);

    s_zap_request_destroy (&request);
    free (metabuf);
    return 0;
}


void domain_auth (zsock_t *pipe, void *certs)
{
    self_t *self = s_self_new (pipe, (certs_t *)certs);
    assert (self);

    //  Signal successful initialization
    zsock_signal (pipe, 0);

    while (!self->terminated) {
        zsock_t *which = (zsock_t *) zpoller_wait (self->poller, -1);
        if (which == self->pipe)
            s_self_handle_pipe (self);
        else
        if (which == self->handler)
            s_self_authenticate (self);
        else
        if (zpoller_terminated (self->poller))
            break;          //  Interrupted
    }
    s_self_destroy (&self);
}

