# scapy3k for RPL or "IPv6 Routing Protocol for Low-Power and Lossy Networks" #

## Supported Messages and Options ##

### RFC 6550 ###

ICMPv6 RPL Control Messages:

| Abbr.   | Message                                          | Class               | Ref in RFC 6550                                        |
|---------|--------------------------------------------------|---------------------|--------------------------------------------------------|
| DIS     | DODAG Information Solicitation                   | `ICMPv6RPL_DIS`     | [6.2](https://tools.ietf.org/html/rfc6550#section-6.2) |
| DIO     | DODAG Information Object                         | `ICMPv6RPL_DIO`     | [6.3](https://tools.ietf.org/html/rfc6550#section-6.3) |
| DAO     | Destination Advertisement Object                 | `ICMPv6RPL_DAO`     | [6.4](https://tools.ietf.org/html/rfc6550#section-6.4) |
| DAO-ACK | Destination Advertisement Object Acknowledgement | `ICMPv6RPL_DAO_ACK` | [6.5](https://tools.ietf.org/html/rfc6550#section-6.5) |
| CC      | Consistency Check                                | `ICMPv6RPL_CC`      | [6.6](https://tools.ietf.org/html/rfc6550#section-6.6) |

RPL Control Message Options:

| Option                  | Class                              | Ref in RFC 6550                                              |
|-------------------------|------------------------------------|--------------------------------------------------------------|
| Pad1                    | `ICMPv6RPLOptPad1`                 | [6.7.2](https://tools.ietf.org/html/rfc6550#section-6.7.2)   |
| PadN                    | `ICMPv6RPLOptPadN`                 | [6.7.3](https://tools.ietf.org/html/rfc6550#section-6.7.3)   |
| DAG Metric Container    | `ICMPv6RPLOptDAGMetricContainer`   | [6.7.4](https://tools.ietf.org/html/rfc6550#section-6.7.4)   |
| Route Information (RIO) | `ICMPv6RPLOptRouteInformation`     | [6.7.5](https://tools.ietf.org/html/rfc6550#section-6.7.5)   |
| DODAG Configuration     | `ICMPv6RPLOptDODAGConfiguration`   | [6.7.6](https://tools.ietf.org/html/rfc6550#section-6.7.6)   |
| RPL Target              | `ICMPv6RPLOptRPLTarget`            | [6.7.7](https://tools.ietf.org/html/rfc6550#section-6.7.7)   |
| Transit Information     | `ICMPv6RPLOptTransitInformation`   | [6.7.8](https://tools.ietf.org/html/rfc6550#section-6.7.8)   |
| Solicited Information   | `ICMPv6RPLOptSolicitedInformation` | [6.7.9](https://tools.ietf.org/html/rfc6550#section-6.7.9)   |
| Prefix Information      | `ICMPv6RPLOptPrefixInformation`    | [6.7.10](https://tools.ietf.org/html/rfc6550#section-6.7.10) |
| RPL Target Descriptor   | `ICMPv6RPLOptRPLTargetDescriptor`  | [6.7.11](https://tools.ietf.org/html/rfc6550#section-6.7.11) |

### RFC 6551 ###

Node/Link Metric/Constraint Objects:

| Object                                    | Class                 | Ref in RFC 6551                                            |
|-------------------------------------------|-----------------------|------------------------------------------------------------|
| Node State and Attribute Object           | `RPLMetricNSA`        | [3.1](https://tools.ietf.org/html/rfc6551#section-3.1)     |
| Node Energy Object                        | `RPLMetricNE`         | [3.2](https://tools.ietf.org/html/rfc6551#section-3.2)     |
| Hop Count Object                          | `RPLMetricHP`         | [3.3](https://tools.ietf.org/html/rfc6551#section-3.3)     |
| Throughput                                | `RPLMetricThroughput` | [4.1](https://tools.ietf.org/html/rfc6551#section-4.1)     |
| Latency                                   | `RPLMetricLatency`    | [4.2](https://tools.ietf.org/html/rfc6551#section-4.2)     |
| The Link Quality Level Reliability Metric | `RPLMetricLQL`        | [4.3.1](https://tools.ietf.org/html/rfc6551#section-4.3.1) |
| The ETX Reliability Object                | `RPLMetricETX`        | [4.3.2](https://tools.ietf.org/html/rfc6551#section-4.3.2) |
| Link Color Object Description             | `RPLMetricLC`         | [4.4.1](https://tools.ietf.org/html/rfc6551#section-4.4.1) |

### RFC 6554 ###

RPL Source Routing Header:

| Header                          | Class                        | Ref in RFC 6554                                    |
|---------------------------------|------------------------------|----------------------------------------------------|
| RPL Source Routing Header (SRH) | `IPv6ExtHdrRPLSourceRouting` | [3](https://tools.ietf.org/html/rfc6554#section-3) |

### RFC 6775 ###

Neighbor Discovery Options:

| Option                             | Class             | Ref in RFC 6775                                        |
|------------------------------------|-------------------|--------------------------------------------------------|
| Address Registration Option        | `ICMPv6NDOptARO`  | [4.1](https://tools.ietf.org/html/rfc6775#section-4.1) |
| 6LoWPAN Context Option             | `ICMPv6NDOpt6CO`  | [4.2](https://tools.ietf.org/html/rfc6775#section-4.2) |
| Authoritative Border Router Option | `ICMPv6NDOptARBO` | [4.3](https://tools.ietf.org/html/rfc6775#section-4.3) |

Duplicate Address Messages:

| Message                        | Class          | Ref in RFC 6775                                        |
|--------------------------------|----------------|--------------------------------------------------------|
| Duplicate Address Request      | `ICMPv6ND_DAR` | [4.4](https://tools.ietf.org/html/rfc6775#section-4.4) |
| Duplicate Address Confirmation | `ICMPv6ND_DAC` | [4.4](https://tools.ietf.org/html/rfc6775#section-4.4) |
