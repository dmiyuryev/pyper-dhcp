# DHCP behaviour

PyperDHCP implements the DHCPv4 server side of
[RFC 2131](https://www.rfc-editor.org/rfc/rfc2131) for one subnet, for
Ethernet clients, either on the local link or through relay agents.

## Supported messages

| Client message | Server action |
| --- | --- |
| `DHCPDISCOVER` | Reserves an address for 60 seconds and replies with `DHCPOFFER`. If the pool is exhausted, there is no reply. |
| `DHCPREQUEST` | Replies with `DHCPACK` and stores the lease, or with `DHCPNAK` if the address cannot be given to this client. Requests without a requested address or `ciaddr` are ignored. |
| `DHCPRELEASE` | Frees the client's lease. |
| `DHCPDECLINE` | Takes the address out of use for one hour. |
| `DHCPINFORM` | Replies with `DHCPACK` carrying network settings but no lease. |

`REQUEST`, `RELEASE` and `DECLINE` messages that name another server in
option 54 (server identifier) are ignored, as RFC 2131 §4.3 requires. The
server also ignores BOOTREPLY packets, non-Ethernet hardware types, packets
relayed through more than 16 hops, and malformed packets.

## Address allocation

* A new client gets the lowest free address in the pool. Freed addresses are
  reused straight away, so addresses are handed out from the bottom of the
  pool up, without gaps.
* A client that already holds a lease or an open offer gets the same address
  again.
* Reserved addresses, addresses held by other clients and quarantined
  addresses are skipped.
* A client with a reservation always gets its reserved address. If that
  address is still leased to someone else or is quarantined, the client gets
  no offer.

## Reply options

Every `OFFER` and `ACK` carries the subnet mask (option 1). The gateway
(option 3) and DNS servers (option 6) are included if they are configured and
the client either asked for them in its parameter request list (option 55) or
sent no list at all.

Lease replies also carry the lease time (option 51), the renewal time T1
(option 58, half the lease) and the rebinding time T2 (option 59, 7/8 of the
lease). `INFORM` replies do not include these three options.

Following RFC 2131 §4.3.2, `DHCPNAK` contains only the message type and the
server identifier.

## Where replies are sent

Following RFC 2131 §4.1:

| Request | Destination |
| --- | --- |
| Relayed (`giaddr` set) | The relay agent, `giaddr:67`. |
| `DHCPNAK` to a local client | Broadcast, `255.255.255.255:68`. |
| Client with `ciaddr` set (renewing, `INFORM`) | Unicast to `ciaddr:68`. |
| Any other request | Broadcast, `255.255.255.255:68`. |

On Linux, each reply leaves through the interface that received the request,
with `server_id` as the source address. If that interface cannot send from
`server_id`, the server falls back to normal routing.

## Protection against misuse

* **`RELEASE`** is accepted only from the lease owner. A direct (not relayed)
  release must come from the address being released.
* **`DECLINE`** is accepted only from the client that holds or was offered the
  address, so no other client can take pool addresses out of use.
* **Rate limiting.** Packets above `max_packets_per_second` are dropped, and
  the number of dropped packets is logged at most once every 10 seconds.

Rate limiting does not protect against pool exhaustion by clients that spoof
MAC addresses. Use DHCP snooping and port security on the switch for that.
