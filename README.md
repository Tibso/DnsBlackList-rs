##### [Early in development]

# DnsBlackList-rs

DNS server with custom rules using [Trust-DNS](https://github.com/bluejekyll/trust-dns) and [Redis-rs](https://github.com/redis-rs/redis-rs).

This DNS server **filters queries** using a **blacklist** from a Redis server. The server **lies** to DNS requests asking for domains names that are known as **dangerous or unwanted** to protect its users from them.

# Repository composition

| Folder | Description |
|--------|-------------|
| *dnsblrsd* | Contains the server's daemon source code and its configuration |
| *redis-ctl* | Contains the source code of the tool used to modify the Redis blacklist |

# Goals

+ ***Secure, fast and stable***

+ ***Simple to setup and use***

+ ***Safe Rust only***

+ [TBD] *Optimized for improved resilience against DDoS*

# Server

## Setup

##### [Guide goes here 3Head]

## How does it work?

Upon receiving a request, a worker thread is assigned to the request. Having **multiple threads** allows the server to handle a much **heavier load** than a single-threaded solution would allow.

If the **request is not** a **query**, it is **dropped** and the worker responds a **Refused** response code error.

If the request's **record type is not** **A** or **AAAA**, the request is **forwarded** to other DNS servers to retrieve a **real answer**. **Otherwise**, the request will be **filtered** using its requested domain name.

The requested **domain** name is **matched against** the Redis **blacklist** using the domain name subdomains which are optimally ordered to speed up the matching process.

Redis **searches** for a **rule** for the requested **domain** name. If **no rule** is found, the request is forwarded to other DNS servers to retrieve a **real answer**. **Otherwise**, the value recovered from the rule determines what is done next. The value is **either** the **custom address** that has to be used as answer to this request or it indicates that the **default address** has to be used.

Finally, the response is sent to the client.

If any error occurs during the handling of a request, the worker forwards the approriate error to the client.

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
  delete    Delete a rule or a complete matchclass
  feed      Feed a list of domains to a matchclass
  drop      Drop all matchclasses that match a pattern
  stats     Get stats about IP addresses that match a pattern
  clear     Clear stats about IP addresses that match a pattern
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

**Displays** the daemon's **configuration**.

This command fetches the configuration from Redis that the daemon uses.

## set

``` 
Usage: redis-ctl <PATH_TO_CONFILE> set <MATCHCLASS> [QTYPE [IP]]
```

**Adds** a new **rule** to the **blacklist**.

+ Example 1: add rule with default ipv6

  `[..] set malware#BLAZIT420:not.honey.pot.net. AAAA`

+ Example 2: add rule with custom ipv4

  `[..] set adult#PEG69:daddyissues.com. A 127.0.0.1`

## get

``` 
Usage: redis-ctl <PATH_TO_CONFILE> get <MATCHCLASS>
```

**Retrieves** all the **information** of a **matchclass**.

## delete

``` 
Usage: redis-ctl <PATH_TO_CONFILE> delete <MATCHCLASS> [QTYPE]
```

**Deletes** a **matchclass or** one of its two **rules**.

+ Example 1: delete the complete matchclass

  `[..] delete malware#ICU2:surely.notpwned.net.`

+ Example 2: delete ipv6 rule of matchclass

  `[..] delete malware#ICU2:surely.notpwned.net. AAAA`

## feed

```
Usage: redis-ctl <PATH_TO_CONFILE> feed <PATH_TO_LIST> <MATCHCLASS>
```

**Feeds** a **matchclass** with a **list** read line by line **from a file**.

+ Example:

  `[..] feed rules.list malware#AKM47`

+ Example line 1: line adding both custom rules for a domain name

  `cicada3301.org. 127.0.0.1 ::1`

+ Example line 2: line adding acustom rule for ipv4 and a default rule for ipv6

  `epstein.didnt.kill.himself.tv. 127.0.0.1 AAAA`

+ Example line 3: line adding only a default rule for ipv4

  `sedun.dnes.tv. A`

## drop

```
Usage: redis-ctl <PATH_TO_CONFILE> drop <PATTERN>
```

**Deletes** all **matchclasses** that match a **pattern**.

Redis' **wildcards** (*?) can be used on the pattern.

+ Example:

  `[..] drop malware#ID?????:*`

## stats

```
Usage: redis-ctl <PATH_TO_CONFILE> stats <PATTERN>
```

**Displays** all **stats** that match an IP **pattern**.

Redis' **wildcards** (*?) can be used on the pattern.

+ Example:

  `[..] stats 123.?.??.*`

## clear

```
Usage: redis-ctl <PATH_TO_CONFILE> clear <PATTERN>
```

**Deletes** all **stats** that match an **IP pattern**.

Redis' **wildcards** (*?) can be used on the pattern.

+ Example:

  `[..] clear 123.?.??.*`
