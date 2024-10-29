/*
################################################################################
#  THIS FILE IS 100% GENERATED BY ZPROJECT; DO NOT EDIT EXCEPT EXPERIMENTALLY  #
#  Read the zproject/README.md for information about making permanent changes. #
################################################################################
*/
#ifndef Q_ZYRE_H
#define Q_ZYRE_H

#include "qtzyre.h"

class QT_ZYRE_EXPORT QZyre : public QObject
{
    Q_OBJECT
public:

    //  Copy-construct to return the proper wrapped c types
    QZyre (zyre_t *self, QObject *qObjParent = 0);

    //  Constructor, creates a new Zyre node. Note that until you start the
    //  node it is silent and invisible to other nodes on the network.
    //  The node name is provided to other nodes during discovery. If you
    //  specify NULL, Zyre generates a randomized node name from the UUID.
    explicit QZyre (const QString &name, QObject *qObjParent = 0);

    //  Destructor, destroys a Zyre node. When you destroy a node, any
    //  messages it is sending or receiving will be discarded.
    ~QZyre ();

    //  Return our node UUID string, after successful initialization
    const QString uuid ();

    //  Return our node name, after successful initialization. First 6
    //  characters of UUID by default.
    const QString name ();

    //  Set the public name of this node overriding the default. The name is
    //  provide during discovery and come in each ENTER message.
    void setName (const QString &name);

    //  Set node header; these are provided to other nodes during discovery
    //  and come in each ENTER message.
    void setHeader (const QString &name, const QString &param);

    //  Set verbose mode; this tells the node to log all traffic as well as
    //  all major events.
    void setVerbose ();

    //  Set UDP beacon discovery port; defaults to 5670, this call overrides
    //  that so you can create independent clusters on the same network, for
    //  e.g. development vs. production. Has no effect after zyre_start().
    void setPort (int portNbr);

    //  Set the TCP port bound by the ROUTER peer-to-peer socket (beacon mode).
    //  Defaults to * (the port is randomly assigned by the system).
    //  This call overrides this, to bypass some firewall issues when ports are
    //  random. Has no effect after zyre_start().
    void setBeaconPeerPort (int portNbr);

    //  Set the peer evasiveness timeout, in milliseconds. Default is 5000.
    //  This can be tuned in order to deal with expected network conditions
    //  and the response time expected by the application. This is tied to
    //  the beacon interval and rate of messages received.
    void setEvasiveTimeout (int interval);

    //  Set the peer silence timeout, in milliseconds. Default is 5000.
    //  This can be tuned in order to deal with expected network conditions
    //  and the response time expected by the application. This is tied to
    //  the beacon interval and rate of messages received.
    //  Silence is triggered one second after the timeout if peer has not
    //  answered ping and has not sent any message.
    //  NB: this is currently redundant with the evasiveness timeout. Both
    //  affect the same timeout value.
    void setSilentTimeout (int interval);

    //  Set the peer expiration timeout, in milliseconds. Default is 30000.
    //  This can be tuned in order to deal with expected network conditions
    //  and the response time expected by the application. This is tied to
    //  the beacon interval and rate of messages received.
    void setExpiredTimeout (int interval);

    //  Set UDP beacon discovery interval, in milliseconds. Default is instant
    //  beacon exploration followed by pinging every 1,000 msecs.
    void setInterval (size_t interval);

    //  Set network interface for UDP beacons. If you do not set this, CZMQ will
    //  choose an interface for you. On boxes with several interfaces you should
    //  specify which one you want to use, or strange things can happen.
    //  The interface may by specified by either the interface name e.g. "eth0" or
    //  an IP address associalted with the interface e.g. "192.168.0.1"
    void setInterface (const QString &value);

    //  By default, Zyre binds to an ephemeral TCP port and broadcasts the local
    //  host name using UDP beaconing. When you call this method, Zyre will use
    //  gossip discovery instead of UDP beaconing. You MUST set-up the gossip
    //  service separately using zyre_gossip_bind() and _connect(). Note that the
    //  endpoint MUST be valid for both bind and connect operations. You can use
    //  inproc://, ipc://, or tcp:// transports (for tcp://, use an IP address
    //  that is meaningful to remote as well as local nodes). Returns 0 if
    //  the bind was successful, else -1.
    int setEndpoint (const QString &param);

    //  This options enables a peer to actively contest for leadership in the
    //  given group. If this option is not set the peer will still participate in
    //  elections but never gets elected. This ensures that a consent for a leader
    //  is reached within a group even though not every peer is contesting for
    //  leadership.
    void setContestInGroup (const QString &group);

    //  Set an alternative endpoint value when using GOSSIP ONLY. This is useful
    //  if you're advertising an endpoint behind a NAT.
    void setAdvertisedEndpoint (const QString &value);

    //  Apply a azcert to a Zyre node.
    void setZcert (QZcert *zcert);

    //  Specify the ZAP domain (for use with CURVE).
    void setZapDomain (const QString &domain);

    //  Set-up gossip discovery of other nodes. At least one node in the cluster
    //  must bind to a well-known gossip endpoint, so other nodes can connect to
    //  it. Note that gossip endpoints are completely distinct from Zyre node
    //  endpoints, and should not overlap (they can use the same transport).
    void gossipBind (const QString &param);

    //  Set-up gossip discovery of other nodes. A node may connect to multiple
    //  other nodes, for redundancy paths. For details of the gossip network
    //  design, see the CZMQ zgossip class.
    void gossipConnect (const QString &param);

    //  Set-up gossip discovery with CURVE enabled.
    void gossipConnectCurve (const QString &publicKey, const QString &param);

    //  Unpublish a GOSSIP node from local list, useful in removing nodes from list when they EXIT
    void gossipUnpublish (const QString &node);

    //  Start node, after setting header values. When you start a node it
    //  begins discovery and connection. Returns 0 if OK, -1 if it wasn't
    //  possible to start the node.
    int start ();

    //  Stop node; this signals to other peers that this node will go away.
    //  This is polite; however you can also just destroy the node without
    //  stopping it.
    void stop ();

    //  Join a named group; after joining a group you can send messages to
    //  the group and all Zyre nodes in that group will receive them.
    int join (const QString &group);

    //  Leave a group
    int leave (const QString &group);

    //  Receive next message from network; the message may be a control
    //  message (ENTER, EXIT, JOIN, LEAVE) or data (WHISPER, SHOUT).
    //  Returns zmsg_t object, or NULL if interrupted
    QZmsg * recv ();

    //  Send message to single peer, specified as a UUID string
    //  Destroys message after sending
    int whisper (const QString &peer, QZmsg *msgP);

    //  Send message to a named group
    //  Destroys message after sending
    int shout (const QString &group, QZmsg *msgP);

    //  Send formatted string to a single peer specified as UUID string
    int whispers (const QString &peer, const QString &param);

    //  Send formatted string to a named group
    int shouts (const QString &group, const QString &param);

    //  Return zlist of current peer ids.
    QZlist * peers ();

    //  Return zlist of current peers of this group.
    QZlist * peersByGroup (const QString &name);

    //  Return zlist of currently joined groups.
    QZlist * ownGroups ();

    //  Return zlist of groups known through connected peers.
    QZlist * peerGroups ();

    //  Return the endpoint of a connected peer.
    //  Returns empty string if peer does not exist.
    QString peerAddress (const QString &peer);

    //  Return the value of a header of a conected peer.
    //  Returns null if peer or key doesn't exits.
    QString peerHeaderValue (const QString &peer, const QString &name);

    //  Explicitly connect to a peer
    int requirePeer (const QString &uuid, const QString &endpoint, const QString &publicKey);

    //  Return socket for talking to the Zyre node, for polling
    QZsock * socket ();

    //  Return underlying ZMQ socket for talking to the Zyre node,
    //  for polling with libzmq (base ZMQ library)
    void * socketZmq ();

    //  Print zyre node information to stdout
    void print ();

    //  Return the Zyre version for run-time API detection; returns
    //  major * 10000 + minor * 100 + patch, as a single integer.
    static quint64 version ();

    //  Self test of this class.
    static void test (bool verbose);

    zyre_t *self;
};
#endif //  Q_ZYRE_H
/*
################################################################################
#  THIS FILE IS 100% GENERATED BY ZPROJECT; DO NOT EDIT EXCEPT EXPERIMENTALLY  #
#  Read the zproject/README.md for information about making permanent changes. #
################################################################################
*/