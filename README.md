##### [Early in development]

# DnsBlackList-rs

DNS server with custom rules using [Trust-DNS](https://github.com/bluejekyll/trust-dns) and [Redis-rs](https://github.com/redis-rs/redis-rs).

This DNS server filters queries using a blacklist from a *Redis* server. The server lies to DNS requests asking for domains names that are known as dangerous.

# Repository composition

| Folder | Description |
|--------|-------------|
| dnsblrsd | Contains the server's daemon source code and its configuration |
| redis-ctl | Contains the source code of the tool used to modify the Redis blacklist |

# Goals

+ Secure, fast and stable
+ Optimized for resilience against DDoS [TBD]
+ Simple to setup and use
+ Safe Rust only

# Server

## Setup

##### [Guide goes here 3Head]

## How does it work?

Upon receiving a request, a worker thread is assigned to the request. Having multiple threads allows the server to handle a much heavier load than a single-threaded solution would allow.

If the request is not a query, it is dropped and the worker responds a *Refused* error.

If the request's record type is not A or AAAA, the request is forwarded to other DNS servers to retrieve a real answer. Otherwise, the request will be filtered using its requested domain name.

The requested domain name is matched against the Redis blacklist using the domain name subdomains which are optimally ordered to speed up the matching process.

Redis searches for a rule for the requested domain name. If no rule is found, the request is forwarded to other DNS servers to retrieve a real answer. Otherwise, the value recovered from the rule determines what is done next. The value is either the address that has to be used as answer to this request or it indicates that the default address has to be used.

Finally, the response is sent to the client.

Any error that occurs during the handling of a request is handled and the approriate error is forwarded to the client.

## Supported Record Types

| Unfiltered | Filtered |
|-----------:|----------|
|        TXT | A        |
|        SRV | AAAA     |
|         MX |          |
|        PTR |          |

# Redis-ctl

This is a command-line tool used to modify the Redis blacklist.

```
Usage: redis-ctl <PATH_TO_CONFILE> <COMMAND>

Commands:
  showconf  Show the dnslrd configuration
  set       Add a new rule
  get       Get info about a matchclass
  delete    Delete a rule
  feed      Feed a list of domains to a matchclass
  dump      Dump a complete matchclass
  drop      Drop entries which match a matchclass pattern
  stats     Get stats about IP addresses that match a prefix
  clear     Clear stats about IP addresses that match a prefix
  help      Print this message or the help of the given subcommand(s)

Arguments:
  <PATH_TO_CONFILE>  Path to dnslrd.conf is required

Options:
  -h, --help  Print help
```

## showconf

``` 
Usage: redis-ctl <PATH_TO_CONFILE> showconf
```

Displays the daemon's configuration.

This command fetches the configuration from Redis that the daemon uses.

## set

``` 
Usage: redis-ctl <PATH_TO_CONFILE> set <matchclass> [qtype [ip]]
```

Adds a new rule to the blacklist.

+ Example 1: add rule with default ipv6

  `[..] set malware#BLAZIT420:urcomputerhasvirus.com. AAAA`

+ Example 2: add rule with custom ipv4

  `[..] set adult#TRAP69:daddyissues.net. A 127.0.0.1`

## get

``` 
Usage: redis-ctl <PATH_TO_CONFILE> get <matchclass>
```

Retrieves information about a matchclass.

This command displays all the blacklisted domain names that belong to this matchclass.

## delete



## feed

## dump

## drop

## stats

## clear

## help

