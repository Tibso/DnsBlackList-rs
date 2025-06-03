# **DnsBlackList-rs**

# THIS README IS NOT UP TO DATE ANYMORE

DNS resolver with custom rules using [Hickory DNS](https://github.com/hickory-dns/hickory-dns) and [Redis-rs](https://github.com/redis-rs/redis-rs).

This DNS resolver **filters queries** using a **blacklist** from a Redis database. The resolver **lies** to DNS requests asking for **domains** that are known as **dangerous or unwanted** to **protect** its **users** from them.

# **Repository composition**

| Directory | Description |
|-----------|-------------|
| *dnsblrsd* | Contains the resolver's daemon source code and its configuration |
| *redis-ctl* | Contains the source code of the tool used to modify the blacklist and the daemons configurations stored in the Redis database |

# **Goals**

+ **Fast, secure and reliable**

+ **Simple to setup and operate**

+ **Safe Rust only**

# **Supported systems**

+ **Unix / Linux**

# **Resolver**

## **How does it work?**

Upon receiving a request, a **worker thread** is **assigned to** the **request**. Having multiple threads allows the resolver to handle a much heavier load than a single-threaded solution could.

Based on its **request type** and **query type**, the request will either be **dropped**, **forwarded** to retrieve a **real answer** or **filtered** using its requested **domain name** and the retrieved **answer**.

When **filtered**, the requested **domain** name is **matched against** the Redis **blacklist** using the domain name subdomains which are optimally ordered to speed up the matching process.

Redis **searches** for a **rule** for the requested **domain** name. If **no rule** is found, the request is forwarded to DNS forwarders to retrieve a **real IP** which is also **filtered** against an **IP blacklist**.

**Otherwise**, the value recovered from the rule determines what is done next. The value is **either** the **custom address** that has to be used as **answer** to this request **or** it indicates that the **default address** has to be used as **answer**.

Finally, the **response** is **sent** to the client.

If **any error occurs** during the handling of a request, the worker **responds** the **approriate error** to the client.

## **Filtering**

The following **query types** are filtered:

+ **A**
+ **AAAA**

**Other** query types are simply **forwarded** to other DNS servers.
However, the **returned IPs** are filtered against the **IP blacklist**.

## **Signals**

The resolver keeps listening for signals on a side-task. These signals can be sent to the resolver to **control** some of its **features**.

| Signal | Description |
|--------|-------------|
| SIGHUP | Reloads the daemon's filtering data from the Redis resolver |
| SIGUSR1 | Switches ON/OFF the resolver's filtering |
| SIGUSR2 | Clears the resolver's cache |

# **Redis configuration structure example**

### **Binds**

The **sockets** that the resolver's **daemon** will attempt to **bind to**.

[SET] DBL;binds;*[DAEMON_ID]*

+ TCP=127.0.0.1:53
+ UDP=127.0.0.1:53
+ TCP=[::1] :53
+ UDP=[::1] :53

### **Forwarders**

The **DNS forwarders** that will **handle** the **forwarded requests**.

[SET] DBL;forwarders;*[DAEMON_ID]*

+ 203.0.113.0.1:53
+ [::1] :53

### **Filters**

The **rules** that **filter** the **requests** using their requested **domain**.

[SET] DBL;filters;*[DAEMON_ID]*

+ malware
+ adult
+ ads

Each **rule** is **linked** to a **filter** using its key name. 

[HASH] DBL;R;adult;you.know.what.i.did.last.night.com.

+ A
  + 203.0.113.0.69
+ AAAA
  + 1

[HASH] DBL;R;adult;i.built.that.fire.over.there.com.

+ A
  + 203.0.113.0.42

### **Blocked IPs**

Lists of **IPs** that must be **blocked** from the forwarders' answers. **V4 and V6** lists are **separated**.

[SET] DBL;blocked-ips;*[DAEMON_ID]*

+ 203.0.113.0.42
+ ::42

### **Rule**

A rule **defines** a **domain** that must be lied to.

[HASH] DBL;R;*[FILTER]*;*[DOMAIN]*

+ **A**
+ **AAAA**

**IP addresses** to use.

**1** is a valid value and indicates the resolver to use the **default value** defined in its daemon's configuration.

+ **enabled**

**1** or **0**, indicates an **enabled/disabled** rule.

+ **date**

The **date** when the **rule** was **added** to the blacklist.

+ **source**

The **source** where the rule **originates** from.

# **Setup**

**Prerequisite**

+ **Redis**

---

Firstly, the daemon's **configuration** must be **setup**.
Start by **editing** the `dnsblrsd.conf` file.

Then setup the configuration using `redis-ctl` and the `edit-conf` **subcommands**:

`redis-ctl path_to_dnsblrsd.conf edit-conf`

Next, **place** the provided `dnsblrsd.service` **file into** the `/etc/systemd/system` **directory**.

The `dnsblrsd.service` file **must be updated** on a **per-user basis**. The **paths** variables **must be changed** to match your user's **environment**. The paths variables must be changed to the **full paths** to the:

+ *ExecStart*: Daemon's **binary**;
+ *WorkingDirectory*: **Directory** storing the daemon's **configuration file**;
+ *ConditionPathExists*: Daemon's **configuration file**.

Lastly, the `systemctl` **command** is used to **configure** the **service**:

+ **Include** the **new service** in the services system:

  `sudo systemctl daemon-reload`

+ **Start** the service:

  `sudo systemctl start dnsblrsd.service`

+ If the service has to **start** on **every boot**:

  `sudo systemctl enable dnsblrsd.service`

+ To **remove** from **every boot**:

  `sudo systemctl disable dnsblrsd.service`

## **Important Notes**

### **DO**

+ **Modify** the **environment variable** `TOKIO_WORKER_THREADS` through the **service file** to **define** the **number of threads** the runtime has to **use**. The **optimum number of threads relies on what is choking performance**. **High I/O latency** will **require more threads** to **keep** the **system busy**, otherwise some threads would remain idle while waiting on I/O. Try to **find** the **sweet spot** for your system and network. ***This can improve performance*** but the default value should do the trick.

### **DO NOT**

+ **Use** a **superuser** to **run** the **resolver**. **Create** a new **user** with **limited privileges** to run the resolver with. Even though this resolver's stability was thoroughly checked via fuzzing, running the resolver on **elevated privileges** would **allow** an **unforeseen vulnerability** to **wreak havoc** on the system. A new **limited user** would **restrain** an **intruder** to the **limited privileges** unless escalation is possible.

# **Redis-ctl**

```
This is a command-line tool used to manipulate the Redis blacklist

Usage: redis-ctl <PATH_TO_CONFILE> <COMMAND>

Commands:
  show-conf      Display the daemon's configuration and the 'redis-ctl' version
  edit-conf      Reconfigure a parameter of the daemon's configuration
  add-rule       Add a new rule
  del-rule       Delete a rule or either of its v4 or v6 IPs
  search-rules   Search for rules using a pattern
  disable-rules  Disable rules that match a pattern
  enable-rules   Enable rules that match a pattern
  auto-feed      Update rules automatically using the "dnsblrs_sources.json" file
  feed           Feed a list of domains to a matchclass
  show-stats     Display stats about IP addresses that match a pattern
  clear-stats    Clear stats about IP addresses that match a pattern
  help           Print this message or the help of the given subcommand(s)

Arguments:
  <PATH_TO_CONFILE>  Path to dnsblrsd.conf is required

Options:
  -h, --help  Print help
```

### ***show-conf***

``` 
Usage: redis-ctl <PATH_TO_CONFILE> show-conf
```

**Displays** the daemon's **configuration**.

### ***add-rule***

``` 
Usage: redis-ctl <PATH_TO_CONFILE> add-rule <FILTER> <SOURCE> <DOMAIN> [IP1/QTYPE] [IP2/QTYPE]
```

**Adds** a new **rule** to the **blacklist**.

+ Example 1: add rule with default ipv6

  `[..] set-rule malware ezy not.honey.pot.net AAAA`

+ Example 2: add rule with custom ipv4

  `[..] set-rule adult pr0n daddyissues.com A 203.0.113.0.42`  

### ***del-rule***

``` 
Usage: redis-ctl <PATH_TO_CONFILE> del-rule <FILTER> <DOMAIN> [QTYPE]
```

**Deletes** a **whole rule** or **one** of its two **qtypes**.

+ Example 1: delete the complete rule (both v4 and v6 qtypes)

  `[..] del-rule malware surely.notpwned.net`

+ Example 2: delete ipv6 qtype of rule

  `[..] del-rule malware surely.notpwned.net AAAA`

### ***search-rules***

```
Usage: redis-ctl <PATH_TO_CONFILE> search-rules <FILTER> <PATTERN>
```

**Searches** for all the **rules** in the blacklist that match a **pattern**.

+ Example:

  `[..] disable-rules malware *.notpwned.???`

### ***disable-rules***

```
Usage: redis-ctl <PATH_TO_CONFILE> disable-rules <FILTER> <PATTERN>
```

**Disables** all the **rules** that match a **pattern**.

Redis **wildcards** (*?) can be used on the pattern.

### ***enable-rules***

```
Usage: redis-ctl <PATH_TO_CONFILE> enable-rules <FILTER> <PATTERN>
```

**Enables** all the **rules** that match a **pattern**.

Redis **wildcards** (*?) can be used on the pattern.

### ***auto-feed***

```
Usage: redis-ctl <PATH_TO_CONFILE> auto-feed <PATH_TO_SOURCES>
```

**Automatically updates** the **blacklist** by **downloading** domains lists listed in the "**dnsblrsd_sources.json**" file.

### ***feed***

```
Usage: redis-ctl <PATH_TO_CONFILE> feed <PATH_TO_LIST> <FILTER> <SOURCE>
```

**Feeds** a **filter** with a **list** read line by line **from a file**. Each line should represent a rule.

+ Example:

  `[..] feed rules.list malware ezy`

+ Example line 1: line adding both custom rules for a domain name

  `cicada3301.org. 127.0.0.1 ::1`

+ Example line 2: line adding a custom rule for ipv4 and a default rule for ipv6

  `epstein.didnt.kill.himself.tv. 127.0.0.1 AAAA`

+ Example line 3: line adding only a default rule for ipv4

  `sedun.dnes.tv. A`

### ***show-stats***

```
Usage: redis-ctl <PATH_TO_CONFILE> show-stats <IP_PATTERN>
```

**Displays** all **stats** that match an IP **pattern**.

Redis **wildcards** (*?) can be used on the IP pattern.

+ Example:

  `[..] show-stats 123.?.??.*`

### ***clear-stats***

```
Usage: redis-ctl <PATH_TO_CONFILE> clear-stats <IP_PATTERN>
```

**Deletes** all **stats** that match an **IP pattern**.

Redis **wildcards** (*?) can be used on the IP pattern.

## ***edit-conf***

```
Reconfigure a parameter of the daemon's configuration

Usage: redis-ctl <PATH_TO_CONFILE> edit-conf <COMMAND>

Commands:
  add-binds           Add new binds
  remove-binds        Remove binds
  add-forwarders      Add new forwarders
  remove-forwarders   Remove forwarders
  add-blocked-ips     Add new blocked IPs
  remove-blocked-ips  Removed blocked IPs
  add-filters         Add filters
  remove-filters      Remove filters
  help                Print this message or the help of the given subcommand(s)

Options:
  -h, --help  Print help

```

### ***add-binds***

```
Usage: redis-ctl <PATH_TO_CONFILE> edit-conf add-binds <BIND1> [BIND2 BIND3 ...]
```

**Adds binds** to the daemon's **configuration**.

+ Example:

  `[...] edit-conf add-binds UDP=127.0.0.1:53 TCP=[::1]:53`

### ***remove-binds***

```
Usage: redis-ctl <PATH_TO_CONFILE> edit-conf remove-binds <BIND1> [BIND2 BIND3 ...]
```

**Removes binds** from the daemon's **configuration**.

### ***add-forwarders***

```
Usage: redis-ctl <PATH_TO_CONFILE> edit-conf add-forwarders <FORWARDER1> [FORWARDER2 FORWARDER3 ...]
```

**Adds forwarders** to the daemon's **configuration**.

+ Example:

  `[...] edit-conf add-forwarders 203.0.113.0.2:53 [2001:DB8::3]:53`

### ***remove-forwarders***

```
Usage: redis-ctl <PATH_TO_CONFILE> edit-conf remove-forwarders <FORWARDER1> [FORWARDER2 FORWARDER3 ...]
```

**Removes forwarders** from the daemon's **configuration**.

### ***add-blocked-ips***

```
Usage: redis-ctl <PATH_TO_CONFILE> edit-conf add-blocked-ips <IP1> [IP2 IP3 ...]
```

**Adds blocked IPs** to the daemon's **configuration**.

### ***remove-blocked-ips***

```
Usage: redis-ctl <PATH_TO_CONFILE> edit-conf remove-blocked-ips <IP1> [IP2 IP3 ...]
```

**Removes blocked IPs** from the daemon's **configuration**.

### ***add-filters***

```
Usage: redis-ctl <PATH_TO_CONFILE> edit-conf add-filters <FILTER1> [FILTER2 FILTER3 ...]
```
**Adds** one or more **filters** to the blacklist.

### ***remove-filters***

```
Usage: redis-ctl <PATH_TO_CONFILE> edit-conf remove-filters <FILTER1> [FILTER2 FILTER3 ...]
```

**Removes** one or more **filters** from the blacklist.
