# scapy3k for RPL

## Supported Messages and Options ##

### RFC 6550 ###

ICMPv6 RPL Control Messages:

| Message                                                    | Class                                     | Ref in RFC 6550                                        |
|------------------------------------------------------------|-------------------------------------------|--------------------------------------------------------|
| DODAG Information Solicitation (DIS)                       | [`ICMPv6RPL_DIS`](#ICMPv6RPL_DIS)         | [6.2](https://tools.ietf.org/html/rfc6550#section-6.2) |
| DODAG Information Object (DIO)                             | [`ICMPv6RPL_DIO`](#ICMPv6RPL_DIO)         | [6.3](https://tools.ietf.org/html/rfc6550#section-6.3) |
| Destination Advertisement Object (DAO)                     | [`ICMPv6RPL_DAO`](#ICMPv6RPL_DAO)         | [6.4](https://tools.ietf.org/html/rfc6550#section-6.4) |
| Destination Advertisement Object Acknowledgement (DAO-ACK) | [`ICMPv6RPL_DAO_ACK`](#ICMPv6RPL_DAO_ACK) | [6.5](https://tools.ietf.org/html/rfc6550#section-6.5) |
| Consistency Check (CC)                                     | [`ICMPv6RPL_CC`](#ICMPv6RPL_CC)           | [6.6](https://tools.ietf.org/html/rfc6550#section-6.6) |

RPL Control Message Options:

| Option                  | Class                                                                   | Ref in RFC 6550                                              |
|-------------------------|-------------------------------------------------------------------------|--------------------------------------------------------------|
| Pad1                    | [`ICMPv6RPLOptPad1`](#ICMPv6RPLOptPad1)                                 | [6.7.2](https://tools.ietf.org/html/rfc6550#section-6.7.2)   |
| PadN                    | [`ICMPv6RPLOptPadN`](#ICMPv6RPLOptPadN)                                 | [6.7.3](https://tools.ietf.org/html/rfc6550#section-6.7.3)   |
| DAG Metric Container    | [`ICMPv6RPLOptDAGMetricContainer`](#ICMPv6RPLOptDAGMetricContainer)     | [6.7.4](https://tools.ietf.org/html/rfc6550#section-6.7.4)   |
| Route Information (RIO) | [`ICMPv6RPLOptRouteInformation`](#ICMPv6RPLOptRouteInformation)         | [6.7.5](https://tools.ietf.org/html/rfc6550#section-6.7.5)   |
| DODAG Configuration     | [`ICMPv6RPLOptDODAGConfiguration`](#ICMPv6RPLOptDODAGConfiguration)     | [6.7.6](https://tools.ietf.org/html/rfc6550#section-6.7.6)   |
| RPL Target              | [`ICMPv6RPLOptRPLTarget`](#ICMPv6RPLOptRPLTarget)                       | [6.7.7](https://tools.ietf.org/html/rfc6550#section-6.7.7)   |
| Transit Information     | [`ICMPv6RPLOptTransitInformation`](#ICMPv6RPLOptTransitInformation)     | [6.7.8](https://tools.ietf.org/html/rfc6550#section-6.7.8)   |
| Solicited Information   | [`ICMPv6RPLOptSolicitedInformation`](#ICMPv6RPLOptSolicitedInformation) | [6.7.9](https://tools.ietf.org/html/rfc6550#section-6.7.9)   |
| Prefix Information      | [`ICMPv6RPLOptPrefixInformation`](#ICMPv6RPLOptPrefixInformation)       | [6.7.10](https://tools.ietf.org/html/rfc6550#section-6.7.10) |
| RPL Target Descriptor   | [`ICMPv6RPLOptRPLTargetDescriptor`](#ICMPv6RPLOptRPLTargetDescriptor)   | [6.7.11](https://tools.ietf.org/html/rfc6550#section-6.7.11) |

### RFC 6551 ###

Node/Link Metric/Constraint Objects:

| Object                                    | Class                                         | Ref in RFC 6551                                            |
|-------------------------------------------|-----------------------------------------------|------------------------------------------------------------|
| Node State and Attribute Object           | [`RPLMetricNSA`](#RPLMetricNSA)               | [3.1](https://tools.ietf.org/html/rfc6551#section-3.1)     |
| Node Energy Object                        | [`RPLMetricNE`](#RPLMetricNE)                 | [3.2](https://tools.ietf.org/html/rfc6551#section-3.2)     |
| Hop Count Object                          | [`RPLMetricHP`](#RPLMetricHP)                 | [3.3](https://tools.ietf.org/html/rfc6551#section-3.3)     |
| Throughput                                | [`RPLMetricThroughput`](#RPLMetricThroughput) | [4.1](https://tools.ietf.org/html/rfc6551#section-4.1)     |
| Latency                                   | [`RPLMetricLatency`](#RPLMetricLatency)       | [4.2](https://tools.ietf.org/html/rfc6551#section-4.2)     |
| The Link Quality Level Reliability Metric | [`RPLMetricLQL`](#RPLMetricLQL)               | [4.3.1](https://tools.ietf.org/html/rfc6551#section-4.3.1) |
| The ETX Reliability Object                | [`RPLMetricETX`](#RPLMetricETX)               | [4.3.2](https://tools.ietf.org/html/rfc6551#section-4.3.2) |
| Link Color Object Description             | [`RPLMetricLC`](#RPLMetricLC)                 | [4.4.1](https://tools.ietf.org/html/rfc6551#section-4.4.1) |

### RFC 6554 ###

RPL Source Routing Header:

| Header                          | Class                                                       | Ref in RFC 6554                                    |
|---------------------------------|-------------------------------------------------------------|----------------------------------------------------|
| RPL Source Routing Header (SRH) | [`IPv6ExtHdrRPLSourceRouting`](#IPv6ExtHdrRPLSourceRouting) | [3](https://tools.ietf.org/html/rfc6554#section-3) |

### RFC 6775 ###

Neighbor Discovery Options:

| Option                             | Class                                 | Ref in RFC 6775                                        |
|------------------------------------|---------------------------------------|--------------------------------------------------------|
| Address Registration Option        | [`ICMPv6NDOptARO`](#ICMPv6NDOptARO)   | [4.1](https://tools.ietf.org/html/rfc6775#section-4.1) |
| 6LoWPAN Context Option             | [`ICMPv6NDOpt6CO`](#ICMPv6NDOpt6CO)   | [4.2](https://tools.ietf.org/html/rfc6775#section-4.2) |
| Authoritative Border Router Option | [`ICMPv6NDOptARBO`](#ICMPv6NDOptARBO) | [4.3](https://tools.ietf.org/html/rfc6775#section-4.3) |

Duplicate Address Messages:

| Message                        | Class                           | Ref in RFC 6775                                        |
|--------------------------------|---------------------------------|--------------------------------------------------------|
| Duplicate Address Request      | [`ICMPv6ND_DAR`](#ICMPv6ND_DAR) | [4.4](https://tools.ietf.org/html/rfc6775#section-4.4) |
| Duplicate Address Confirmation | [`ICMPv6ND_DAC`](#ICMPv6ND_DAC) | [4.4](https://tools.ietf.org/html/rfc6775#section-4.4) |

## Class
### <a name="ICMPv6RPL_DIS"></a>ICMPv6RPL_DIS

| Attribute | Type   | Width   | Default | Notes                                               |
|-----------|--------|---------|---------|-----------------------------------------------------|
| type      | Byte   | 8 bits  |     155 |                                                     |
| code      | Byte   | 8 bits  |       0 |                                                     |
| cksum     | XShort | 16 bits |    None | checksum is automatically set unless nothing is set |
| flags     | Byte   | 8 bits  |       0 | Reserved bits                                       |
| reserved  | Byte   | 8 bits  |       0 | Reserved field                                      |

Example:
```python
a = ICMPv6RPL_DIS()
a.show()
####[ RPL Control Message - DODAG Information Solicitation ]###
#     type      = RPL Control Message
#     code      = DIS
#     cksum     = None
#     flags     = 0
#     reserved  = 0
#
```
### <a name="ICMPv6RPL_DIO"></a>ICMPv6RPL_DIO

| Attribute  | Field Type | Width    | Default | Notes                                                    |
|------------|------------|----------|---------|----------------------------------------------------------|
| type       | Byte       | 8 bits   |     155 |                                                          |
| code       | Byte       | 8 bits   |       1 |                                                          |
| cksum      | XShort     | 16 bits  |    None | checksum is automatically set as long as nothing is set. |
| instanceid | Byte       | 8 bits   |       0 | RPL Instance ID                                          |
| version    | Byte       | 8 bits   |       0 | DODAG Version Number                                     |
| rank       | Byte       | 8 bits   |       0 | Rank of the sender                                       |
| G          | Bit        | 1 bit    |       0 | Grounded flag; if it's set, the DODAG is grounded.       |
| Z          | Bit        | 1 bit    |       0 | Zero flag; should be always zero.                        |
| mop        | Bit        | 3 bits   |       0 | Mode of Operation                                        |
| prf        | Bit        | 3 bits   |       0 | DODAGPreference                                          |
| dtsn       | Byte       | 8 bits   |       0 | Destination Advertisement Trigger Sequence Number (DTSN) |
| flags      | Byte       | 8 bits   |       0 | Reserved flags                                           |
| reserved   | Byte       | 8 bits   |       0 | Reserved field                                           |
| dodagid    | IP6        | 128 bits |      :: | DODAGID                                                  |

```python
```

### <a name="ICMPv6RPL_DAO"></a>ICMPv6RPL_DAO

| Attribute   | Field Type | Width    | Default | Notes                                                             |
|-------------|------------|----------|---------|-------------------------------------------------------------------|
| type        | Byte       | 8 bits   |     155 |                                                                   |
| code        | Byte       | 8 bits   |       2 |                                                                   |
| cksum       | XShort     | 16 bits  |    None | checksum is automatically set as long as nothing is set.          |
| instanceid  | Byte       | 8 bits   |       0 | RPL Instance ID                                                   |
| K           | Bit        | 1 bit    |       0 | DAO-ACK flag                                                      |
| D           | Bit        | 1 bit    |       0 | DODAGID flag which indicates DODAGID field (`dodagid`) is present |
| flags       | Bit        | 6 bits   |       0 | Reserved bits                                                     |
| reserved    | Byte       | 8 bits   |       0 | Reserved field                                                    |
| daosequence | Byte       | 8 bits   |       0 | Sequence number of DAO                                            |
| dodagid     | IP6        | 128 bits |      :: | DODAGID (present if `D` is 1)                                     |

### <a name="ICMPv6RPL_DAO_ACK"></a>ICMPv6RPL_DAO_ACK

| Attribute   | Field Type | Width    | Default | Notes                                                             |
|-------------|------------|----------|---------|-------------------------------------------------------------------|
| type        | Byte       | 8 bits   |     155 |                                                                   |
| code        | Byte       | 8 bits   |       3 |                                                                   |
| cksum       | XShort     | 16 bits  |    None | checksum is automatically set as long as nothing is set.          |
| instanceid  | Byte       | 8 bits   |       0 | RPL Instance ID                                                   |
| D           | Bit        | 1 bit    |       0 | DODAGID flag which indicates DODAGID field (`dodagid`) is present |
| reserved    | Bit        | 7 bits   |       0 | Reserved bits                                                     |
| daosequence | Byte       | 8 bits   |       0 | Sequence number of the correspondent DAO                          |
| status      | Byte       | 8 bits   |       0 | It Indicates the completion of DAO.                               |
| dodagid     | IP6        | 128 bits |      :: | DODAGID (present if `D` is 1)                                     |

```python
```

### <a name="ICMPv6RPL_CC"></a>ICMPv6RPL_CC

| Attribute  | Field Type | Width    | Default | Notes                                             |
|------------|------------|----------|---------|---------------------------------------------------|
| type       | Byte       | 8 bits   |     155 |                                                   |
| code       | Byte       | 8 bits   |       4 |                                                   |
| cksum      | XShort     | 16 bits  |    None | Automatically computed as long as nothing is set. |
| instanceid | Byte       | 8 bits   |       0 | RPL Instance ID                                   |
| R          | Bit        | 1 bit    |       0 | R (response) flag; set if it's a response.        |
| flags      | Bit        | 7 bits   |       0 | Reserved bits                                     |
| ccnonce    | Byte       | 8 bits   |       0 | CC Nonce                                          |
| dodagid    | IP6        | 128 bits |      :: | DODAG  ID                                         |
| dstcounter | Int        | 32 bits  |       0 | Destination Counter                               |

```python
```
### <a name="ICMPv6RPLOptPad1"></a>ICMPv6RPLOptPad1

| Attribute | Field Type | Width  | Default | Notes |
|-----------|------------|--------|---------|-------|
| type      | Byte       | 8 bits |       0 |       |

### <a name="ICMPv6RPLOptPadN"></a>ICMPv6RPLOptPadN

| Attribute | Field Type | Width    | Default | Notes                |
|-----------|------------|----------|---------|----------------------|
| type      | Byte       | 8 bits   |       1 |                      |
| len       | Byte       | 8 bits   |       0 |                      |
| padding   | StrLen     | variable |    None | Present if `len` > 0 |


### <a name="ICMPv6RPLOptDAGMetricContainer"></a>ICMPv6RPLOptDAGMetricContainer

| Attribute | Field Type | Width    | Default | Notes                |
|-----------|------------|----------|---------|----------------------|
| type      | Byte       | 8 bits   |       2 |                      |
| len       | Byte       | 8 bits   |       0 |                      |

Example:
```python
```
### <a name="ICMPv6RPLOptRouteInformation"></a>ICMPv6RPLOptRouteInformation

| Attribute | Field Type | Width    | Default | Notes                                            |
|-----------|------------|----------|---------|--------------------------------------------------|
| type      | Byte       | 8 bits   |       3 |                                                  |
| len       | FieldLen   | 8 bits   |    None | Automatically computed as long as nothing is set |
| prefixlen | Byte       | 8 bits   |       0 | Prefix Length indicating valid bits in `prefix`  |
| reserved1 | Bit        | 3 bits   |       0 | Reserved bits                                    |
| prf       | Bit        | 2 bits   |       0 | Route Preference                                 |
| reserved2 | Bit        | 3 bits   |       0 | Reserved bits                                    |
| lifetime  | Int        | 32 bits  |       0 | Route Lifetime in seconds                        |
| prefix    | Prefix6    | variable |    ::/0 | Prefix                                           |

Example:
```python
```

### <a name="ICMPv6RPLOptDODAGConfiguration"></a>ICMPv6RPLOptDODAGConfiguration

| Attribute       | Field Type | Width   | Default | Notes                           |
|-----------------|------------|---------|---------|---------------------------------|
| type            | Byte       | 8 bits  |       4 |                                 |
| len             | Byte       | 8 bits  |      14 |                                 |
| flags           | Bit        | 4 bits  |       0 |                                 |
| A               | Bit        | 1 bit   |       0 | Authentication Enabled (A) flag |
| pcs             | Bit        | 3 bits  |       0 | Path Control Size (PCS)         |
| diointdouble    | Byte       | 8 bits  |       0 | DIO Interval Doublings          |
| diointmin       | Byte       | 8 bits  |       0 | DIO Inerval Min (Imin)          |
| dioredundancy   | Byte       | 8 bits  |       0 | DIO Redundancy Constant         |
| maxrankinc      | Short      | 16 bits |       0 | Max Rank Increase               |
| minhoprankinc   | Short      | 16 bits |       0 | Min Hop Rank Increase           |
| ocp             | Short      | 16 bits |       0 | Object Code Point (OCP)         |
| reserved        | Byte       | 8 bits  |       0 | Reserved field                  |
| defaultlifetime | Byte       | 8 bits  |       0 | Default Lifetime                |
| lifetimeunit    | Short      | 16 bits |       0 | Lifetime Unit                   |

### <a name="ICMPv6RPLOptRPLTarget"></a>ICMPv6RPLOptRPLTarget

| Attribute | Field Type | Width    | Default | Notes         |
|-----------|------------|----------|---------|---------------|
| type      | Byte       | 8 bits   |       5 |               |
| len       | FieldLen   | 8 bits   |    None |               |
| flags     | Bit        | 8 bits   |       0 | Unused field  |
| prefixlen | Byte       | 8 bits   |       0 |               |
| prefix    | Prefix6    | varibale |    ::/0 | Target Prefix |

Example:
```python
```

### <a name="ICMPv6RPLOptTransitInformation"></a>ICMPv6RPLOptTransitInformation

| Attribute | Field Type | Width    | Default | Notes                                                         |
|-----------|------------|----------|---------|---------------------------------------------------------------|
| type      | Byte       | 8 bits   |       6 |                                                               |
| len       | FieldLen   | 8 bits   |    None |                                                               |
| E         | Bit        | 1 bit    |       0 | External (E) flag; set when redistributing an external target |
| flags     | Bit        | 7 btis   |       0 | Reserved bits                                                 |
| control   | Byte       | 8 bits   |       0 | Path Control                                                  |
| sequence  | Byte       | 8 bits   |       0 | Path Sequence                                                 |
| lifetime  | Byte       | 8 bits   |       0 | Path Lifetime                                                 |
| address   | IP6        | 128 bits |    None | Parent Address, Conditional Field                             |

Example:
```python
```

### <a name="ICMPv6RPLOptSolicitedInformation"></a>ICMPv6RPLOptSolicitedInformation

| Attribute  | Field Type | Width    | Default | Notes                          |
|------------|------------|----------|---------|--------------------------------|
| type       | Byte       | 8 bits   |       7 |                                |
| len        | Byte       | 8 bits   |      19 |                                |
| instanceid | Byte       | 8 bit    |       0 | RPL Instance ID                |
| V          | Bit        | 1 bti    |       0 | Version (V) predicate flag     |
| I          | Bit        | 1 bit    |       0 | Instance ID (I) predicate flag |
| D          | Bit        | 1 bit    |       0 | DODAG (D) ID predicate flag    |
| flags      | Bit        | 5 bits   |       0 | Reserved bits                  |
| dodagid    | IP6        | 128 bits |      :: | DODAGID                        |
| version    | Byte       | 8 btis   |       0 | Version Number                 |


Example:
```python
```
### <a name="ICMPv6RPLOptPrefixInformation"></a>ICMPv6RPLOptPrefixInformation

| Attribute         | Field Type | Width    | Default | Notes                                 |
|-------------------|------------|----------|---------|---------------------------------------|
| type              | Byte       | 8 bits   |       8 |                                       |
| len               | Byte       | 8 bits   |      30 |                                       |
| prefixlen         | Byte       | 8 bit    |       0 | Prefix length                         |
| L                 | Bit        | 1 bit    |       0 | On-link flag                          |
| A                 | Bit        | 1 bit    |       0 | Autonomous address-configuration flag |
| R                 | Bit        | 1 bit    |       0 | Router address flag                   |
| reserved1         | Bit        | 5 bits   |       0 | Reserved bits                         |
| validlifetime     | Int        | 32 bits  |       0 | Valid lifetime of the prefix          |
| preferredlifetime | Int        | 32 bits  |       0 | Preferred lifetime of the prefix      |
| reserved2         | Int        | 32 bits  |       0 | Reserved field                        |
| prefix            | IP6        | 128 bits |      :: | Prefix                                |


Example:
```python
```

### <a name="ICMPv6RPLOptRPLTargetDescriptor"></a>ICMPv6RPLOptRPLTargetDescriptor

| Attribute  | Field Type | Width   | Default | Notes |
|------------|------------|---------|---------|-------|
| type       | Byte       | 8 bits  |       9 |       |
| len        | Byte       | 8 bits  |       4 |       |
| descriptor | Int        | 32 bits |       0 |       |

Example:
```python
```

### <a name="RPLMetricNSA"><a/>RPLMetricNSA
| Attribute | Field Type | Width  | Default | Notes                                                                               |
|-----------|------------|--------|---------|-------------------------------------------------------------------------------------|
| type      | Byte       | 8 bits |       1 |                                                                                     |
| reserved1 | Bit        | 6 bits |       0 | Reserved bits                                                                       |
| P         | Bit        | 1 bit  |       0 | P(ath) flag indicating not all nodes along the path record the corresponding metric |
| C         | Bit        | 1 bit  |       0 | Constrained flag                                                                    |
| O         | Bit        | 1 bit  |       0 | Optional flag                                                                       |
| R         | Bit        | 1 bit  |       0 | Routing metric flag                                                                 |
| A         | Bit        | 3 bits |       0 | Aggregation flag                                                                    |
| prec      | Bit        | 4 bits |       0 | Precedence flag                                                                     |
| len       | Byte       | 8 bits |       1 |                                                                                     |
| reserved2 | Byte       | 8 bits |       0 | Reserved field                                                                      |
| flags     | Bit        | 6 bits |       0 | Reserved bits                                                                       |
| a         | Bit        | 1 bit  |       0 | Data aggregation attribute                                                          |
| o         | Bit        | 1 bit  |       0 | Overloaded flag                                                                     |

Example:
```python
```

### <a name="RPLMetricNE"><a/>RPLMetricNE

| Attribute | Field Type | Width  | Default | Notes                                                                               |
|-----------|------------|--------|---------|-------------------------------------------------------------------------------------|
| type      | Byte       | 8 bits |       2 |                                                                                     |
| reserved1 | Bit        | 6 bits |       0 | Reserved bits                                                                       |
| P         | Bit        | 1 bit  |       0 | P(ath) flag indicating not all nodes along the path record the corresponding metric |
| C         | Bit        | 1 bit  |       0 | Constrained flag                                                                    |
| O         | Bit        | 1 bit  |       0 | Optional flag                                                                       |
| R         | Bit        | 1 bit  |       0 | Routing metric flag                                                                 |
| A         | Bit        | 3 bits |       0 | Aggregation flag                                                                    |
| prec      | Bit        | 4 bits |       0 | Precedence flag                                                                     |
| len       | Byte       | 8 bits |       1 |                                                                                     |
| flags     | Bit        | 4 bits |       0 | Reserved bits                                                                       |
| I         | Bit        | 1 bit  |       0 | Included (I) flag                                                                   |
| T         | Bit        | 2 bit  |       0 | Node Type (T) flag                                                                  |
| E         | Bit        | 1 bit  |       0 | Estimation (E) flag                                                                 |
| E_E       | Byte       | 8 bits |       0 | Estimated-Energy                                                                    |

Example:
```python
```

### <a name="RPLMetricHP"><a/>RPLMetricHP

| Attribute | Field Type | Width  | Default | Notes                                                                               |
|-----------|------------|--------|---------|-------------------------------------------------------------------------------------|
| type      | Byte       | 8 bits |       3 |                                                                                     |
| reserved1 | Bit        | 6 bits |       0 | Reserved bits                                                                       |
| P         | Bit        | 1 bit  |       0 | P(ath) flag indicating not all nodes along the path record the corresponding metric |
| C         | Bit        | 1 bit  |       0 | Constrained flag                                                                    |
| O         | Bit        | 1 bit  |       0 | Optional flag                                                                       |
| R         | Bit        | 1 bit  |       0 | Routing metric flag                                                                 |
| A         | Bit        | 3 bits |       0 | Aggregation flag                                                                    |
| prec      | Bit        | 4 bits |       0 | Precedence flag                                                                     |
| len       | Byte       | 8 bits |       0 |                                                                                     |
| reserved2 | Bit        | 4 bits |       0 | Reserved bits                                                                       |
| flags     | Bit        | 4 bits |       0 | Reserved bits                                                                       |
| hopcount  | Byte       | 8 bits |       0 | Hop count                                                                           |

Example:
```python
```
### <a name="RPLMetricThroughput"><a/>RPLMetricThroughput

| Attribute  | Field Type | Width   | Default | Notes                                                                               |
|------------|------------|---------|---------|-------------------------------------------------------------------------------------|
| type       | Byte       | 8 bits  |       4 |                                                                                     |
| reserved1  | Bit        | 6 bits  |       0 | Reserved bits                                                                       |
| P          | Bit        | 1 bit   |       0 | P(ath) flag indicating not all nodes along the path record the corresponding metric |
| C          | Bit        | 1 bit   |       0 | Constrained flag                                                                    |
| O          | Bit        | 1 bit   |       0 | Optional flag                                                                       |
| R          | Bit        | 1 bit   |       0 | Routing metric flag                                                                 |
| A          | Bit        | 3 bits  |       0 | Aggregation flag                                                                    |
| prec       | Bit        | 4 bits  |       0 | Precedence flag                                                                     |
| len        | Byte       | 8 bits  |       0 |                                                                                     |
| throughput | Int        | 32 bits |       0 |                                                                                     |

Example:
```python
```
### <a name="RPLMetricLatency"><a/>RPLMetricLatency

| Attribute | Field Type | Width   | Default | Notes                                                                               |
|-----------|------------|---------|---------|-------------------------------------------------------------------------------------|
| type      | Byte       | 8 bits  |       5 |                                                                                     |
| reserved1 | Bit        | 6 bits  |       0 | Reserved bits                                                                       |
| P         | Bit        | 1 bit   |       0 | P(ath) flag indicating not all nodes along the path record the corresponding metric |
| C         | Bit        | 1 bit   |       0 | Constrained flag                                                                    |
| O         | Bit        | 1 bit   |       0 | Optional flag                                                                       |
| R         | Bit        | 1 bit   |       0 | Routing metric flag                                                                 |
| A         | Bit        | 3 bits  |       0 | Aggregation flag                                                                    |
| prec      | Bit        | 4 bits  |       0 | Precedence flag                                                                     |
| len       | Byte       | 8 btis  |       0 |                                                                                     |
| latency   | Int        | 32 bits |       0 |                                                                                     |

Example:
```python
```

### <a name="RPLMetricLQL"><a/>RPLMetricLQL

| Attribute | Field Type | Width    |       Default | Notes                                                                               |
|-----------|------------|----------|---------------|-------------------------------------------------------------------------------------|
| type      | Byte       | 8 bits   |             6 |                                                                                     |
| reserved1 | Bit        | 6 bits   |             0 | Reserved bits                                                                       |
| P         | Bit        | 1 bit    |             0 | P(ath) flag indicating not all nodes along the path record the corresponding metric |
| C         | Bit        | 1 bit    |             0 | Constrained flag                                                                    |
| O         | Bit        | 1 bit    |             0 | Optional flag                                                                       |
| R         | Bit        | 1 bit    |             0 | Routing metric flag                                                                 |
| A         | Bit        | 3 bits   |             0 | Aggregation flag                                                                    |
| prec      | Bit        | 4 bits   |             0 | Precedence flag                                                                     |
| len       | FieldLen   | variable |             0 | Automatically computed as long as nothing is set.                                   |
| reserved2 | Byte       | 8 bits   |             0 | Reserved field                                                                      |
| lql       | PacketList | variable | RPLLQLType1() | One or more RPLLQLType1()s                                                          |

RPLLQLType1():

| Attribute | Field Type | Width  | Default | Notes                               |
|-----------|------------|--------|---------|-------------------------------------|
| val       | Bit        | 3 bits |       0 | LQL Value                           |
| counter   | Bit        | 5 bits |       0 | Number of links with that LQL value |

Example:
```python
```

### <a name="RPLMetricETX"><a/>RPLMetricETX

| Attribute | Field Type | Width   | Default | Notes                                                                               |
|-----------|------------|---------|---------|-------------------------------------------------------------------------------------|
| type      | Byte       | 8 bits  |       7 |                                                                                     |
| reserved1 | Bit        | 6 bits  |       0 | Reserved bits                                                                       |
| P         | Bit        | 1 bit   |       0 | P(ath) flag indicating not all nodes along the path record the corresponding metric |
| C         | Bit        | 1 bit   |       0 | Constrained flag                                                                    |
| O         | Bit        | 1 bit   |       0 | Optional flag                                                                       |
| R         | Bit        | 1 bit   |       0 | Routing metric flag                                                                 |
| A         | Bit        | 3 bits  |       0 | Aggregation flag                                                                    |
| prec      | Bit        | 4 bits  |       0 | Precedence flag                                                                     |
| len       | Byte       | 8 bits  |       0 |                                                                                     |
| etx       | short      | 16 bits |       0 | You should set `math.round(ETX * 128)` to this field.                               |

Example:
```python
```

### <a name="RPLMetricLC"><a/>RPLMetricLC

| Attribute | Field Type | Width    |      Default | Notes                                                                                  |
|-----------|------------|----------|--------------|----------------------------------------------------------------------------------------|
| type      | Byte       | 8 bits   |            0 |                                                                                        |
| reserved1 | Bit        | 6 bits   |            0 | Reserved bits                                                                          |
| P         | Bit        | 1 bit    |            0 | P(ath) flag indicating not all nodes along the path record the corresponding metric    |
| C         | Bit        | 1 bit    |            0 | Constrained flag                                                                       |
| O         | Bit        | 1 bit    |            0 | Optional flag                                                                          |
| R         | Bit        | 1 bit    |            0 | Routing metric flag                                                                    |
| A         | Bit        | 3 bits   |            0 | Aggregation flag                                                                       |
| prec      | Bit        | 4 bits   |            0 | Precedence flag                                                                        |
| len       | Byte       | 8 bits   |            0 |                                                                                        |
| reserved2 | Byte       | 8 bits   |            0 | Reserved field                                                                         |
| lc        | -          | variable | RPLLCType1() | If C flag is 0, a list of RPLLCTyp1() is set; otherwise a list of RPLLCType2() is set. |

RPLLCType1():

| Attribute | Field Type | Width   | Default | Notes      |
|-----------|------------|---------|---------|------------|
| linkcolor | Bit        | 10 bits |       0 | Link Color |
| counter   | Bit        | 6 bits  |       0 |            |

RPLLCType2():

| Attribute | Field Type | Width   | Default | Notes                                                      |
|-----------|------------|---------|---------|------------------------------------------------------------|
| linkcolor | Bit        | 10 bits |       0 | Link Color                                                 |
| reserved  | Bit        | 5 bits  |       0 |                                                            |
| I         | Bit        | 1 bit   |       0 | The 'I' bit; set if the link color is used as a constraint |

Example:
```python
```
### <a name="IPv6ExtHdrRPLSourceRouting"><a/>IPv6ExtHdrRPLSourceRouting

| Attribute | Field Type | Width    | Default | Notes                                                                     |
|-----------|------------|----------|---------|---------------------------------------------------------------------------|
| nh        | Byte       | 8 bits   |      59 | Next Header                                                               |
| len       | FieldLen   | 8 bits   |    None | Automatically computed as long as nothing is set.                         |
| type      | Byte       | 8 bits   |       3 |                                                                           |
| seglef    | Byte       | 8 bits   |       0 | Segments left                                                             |
| CmprI     | Bit        | 4 bits   |       0 |                                                                           |
| CmprE     | Bit        | 4 bits   |       0 |                                                                           |
| pad       | Bit        | 4 bits   |    None | Automatically computed as long as nothing is set.                         |
| reserved  | Bit        | 20 bits  |       0 | Reserved bits                                                             |
| addresses | FieldList  | variable |      [] | A list of Address6Field(); the length of each address depends on `CmprI`. |
| last      | Address6   | variable |  ::/128 | The length depends on `CmprE`.                                            |
| padding   | StrLen     | varibale |    None | Condtionl Field                                                           |

Example:
```python
```

### <a name="ICMPv6NDOptARO"><a/>ICMPv6NDOptARO

| Attribute  | Field Type | Width   |                 Default | Notes                 |
|------------|------------|---------|-------------------------|-----------------------|
| type       | Byte       | 8 bits  |                      33 |                       |
| len        | Byte       | 8 bits  |                       2 |                       |
| status     | Byte       | 8 bits  |                       0 |                       |
| resereved1 | Byte       | 8 bits  |                       0 | Reserved field        |
| reserved2  | Short      | 16 bits |                       0 | Reserved field        |
| lifetime   | Short      | 16 bits |                       0 | Registration Lifetime |
| eui64      | EUI64      | 64 bits | 00:00:00:00:00:00:00:00 | EUI-64 Identifier     |

Example:
```python
```

### <a name="ICMPv6NDOpt6CO"><a/>ICMPv6NDOpt6CO

| Attribute     | Field Type | Width    | Default | Notes                             |
|---------------|------------|----------|---------|-----------------------------------|
| type          | Byte       | 8 bits   |      34 |                                   |
| len           | Byte       | 8 bits   |       0 |                                   |
| contextlength | Byte       | 8 bits   |       0 | Context Length                    |
| reserved1     | Bit        | 3 bits   |       0 | Reserved bits                     |
| C             | Bit        | 1 bit    |       0 | Compression (C) flag              |
| cid           | Bit        | 4 bits   |       0 | Context Identifier for the prefix |
| reserved2     | Short      | 16 bits  |       0 | Reserved field                    |
| lifetime      | Short      | 16 bits  |       0 | Valid Lifetime                    |
| prefix        | Prefix6    | variable |   ::/64 | Context Prefix                    |

Example:
```python
```

### <a name="ICMPv6NDOptABRO"><a/>ICMPv6NDOptABRO

| Attribute | Field Type | Width    | Default | Notes                                                                                   |
|-----------|------------|----------|---------|-----------------------------------------------------------------------------------------|
| type      | Byte       | 8 bits   |      35 |                                                                                         |
| len       | Byte       | 8 bits   |       3 |                                                                                         |
| version   | Int        | 32 bits  |       0 | In RFC 6775, `version` is defined as a combination of `Version Low` and `Version High`. |
| lifetime  | Short      | 16 bits  |       0 | Valid lifetime                                                                          |
| address   | IP6        | 128 bits |      :: | 6LBR Address                                                                            |

Example:
```python
```

### <a name="ICMPv6ND_DAR"><a/>ICMPv6ND_DAR

| Attribute | Field Type | Width    |                 Default | Notes                                             |
|-----------|------------|----------|-------------------------|---------------------------------------------------|
| type      | Byte       | 8 bits   |                     157 |                                                   |
| code      | Byte       | 8 btis   |                       0 |                                                   |
| cksum     | XShort     | 16 bits  |                    None | Automatically computed as long as nothing is set. |
| reserved  | Byte       | 8 bits   |                       0 | Reserved field                                    |
| lifetime  | Short      | 16 bits  |                       0 | Registration Lifetime in units of 60 seconds      |
| eui64     | EUI64      | 64 bits  | 00:00:00:00:00:00:00:00 | EUI-64 Identifier                                 |
| address   | IP6        | 128 bits |                      :: | Registration Address

Example:
```python
```

### <a name="ICMPv6ND_DAC"><a/>ICMPv6ND_DAC

| Attribute | Field Type | Width    |                 Default | Notes                                             |
|-----------|------------|----------|-------------------------|---------------------------------------------------|
| type      | Byte       | 8 bits   |                     158 |                                                   |
| code      | Byte       | 8 btis   |                       0 |                                                   |
| cksum     | XShort     | 16 bits  |                    None | Automatically computed as long as nothing is set. |
| reserved  | Byte       | 8 bits   |                       0 | Reserved field                                    |
| lifetime  | Short      | 16 bits  |                       0 | Registration Lifetime in units of 60 seconds      |
| eui64     | EUI64      | 64 bits  | 00:00:00:00:00:00:00:00 | EUI-64 Identifier                                 |
| address   | IP6        | 128 bits |                      :: | Registration Address                              |
