##### [Early in development]

# **DnsBlackList-rs**

DNS server with custom rules using [Trust-DNS](https://github.com/bluejekyll/trust-dns) and [Redis-rs](https://github.com/redis-rs/redis-rs).

This DNS server **filters queries** using a **blacklist** from a Redis database. The server **lies** to DNS requests asking for **domains** that are known as **dangerous or unwanted** to **protect** its **users** from them.

# **Repository composition**

| Folder | Description |
|--------|-------------|
| *dnsblrsd* | Contains the server's daemon source code and its configuration |
| *redis-ctl* | Contains the source code of the tool used to modify the blacklist stored in the Redis database |

# **Goals**

+ **Secure, fast and stable**

+ **Simple to setup and operate**

+ **Safe Rust only**

+ [TBD] *Optimized for improved resilience against DDoS*

# **Supported systems**

+ **Unix / Linux**

+ [TBA] *Windows*

# **Server**

## **How does it work?**

Upon receiving a request, a **worker thread** is **assigned to** the **request**. Having multiple threads allows the server to handle a much heavier load than a single-threaded solution would allow.

Based on its **request type** and **query type**, the request will either be **dropped**, **forwarded** to retrieve a **real answer** or **filtered** using its requested **domain name** and the retrieved **answer**.

When **filtered**, the requested **domain** name is **matched against** the Redis **blacklist** using the domain name subdomains which are optimally ordered to speed up the matching process.

Redis **searches** for a **rule** for the requested **domain** name. If **no rule** is found, the request is forwarded to other DNS servers to retrieve a **real IP** which is also **filtered** against an **IP blacklist**.

**Otherwise**, the value recovered from the rule determines what is done next. The value is **either** the **custom address** that has to be used as **answer** to this request **or** it indicates that the **default address** has to be used as **answer**.

Finally, the **response** is **sent** to the client.

If **any error occurs** during the handling of a request, the worker **forwards** the **approriate error** to the client.

## **Supported Query Types**

| Unfiltered | Filtered |
|-----------:|----------|
|        TXT | A        |
|        SRV | AAAA     |
|         MX |          |
|        PTR |          |

## **Signals**

The server keeps listening for signals on a side-task. These signals can be sent to the server **control** some of its **features**.

| Signal | Description |
|-------:|-------------|
| SIGHUP | Reloads the daemon's configuration from the Redis server |
| SIGUSR1 | Switches ON/OFF the server's filtering |
| SIGUSR2 | Clears the resolver's cache |

## **Redis configuration structure example**

### **Binds**

The **sockets** the server's **daemon** will attempt to **bind to**.

[SET] dnsblrsd:binds:*[DAEMON_ID]*

+ TCP=127.0.0.1:53
+ UDP=127.0.0.1:53
+ TCP=::1:53
+ UDP=::1:53

### **Forwarders**

The **DNS servers** that will **handle** the **forwarded requests**.

[SET] dnsblrsd:forwarders:*[DAEMON_ID]*

+ 123.456.789.1:53
+ 123.456.789.2:53

### **Blackhole IPs**

The **default IPs** that will be **answered** to **blocked requests**. These IPs are used unless the matched rule has a specific IP configured as answer.

[SET] dnsblrsd:blackhole_ips:*[DAEMON_ID]*

+ 127.0.0.1
+ ::1

### **Matchclasses**

The **rules** that **filter** the **requests** using their requested **domain**.

[SET] dnsblrsd:matchclasses:*[DAEMON_ID]*

+ malware#IT1#20230419
+ adult#IT2#20230419

Each **rule** is **linked** to its **matchclass** using its **ID**. This is so hashes are easily identified in the database.

[HASH] adult#IT2#20230419:you.know.what.i.did.last.night.com.

+ A
  + 123.456.789.69
+ AAAA
  + 1

[HASH] adult#IT2#20230419:i.built.that.fire.over.there.com.

+ A
  + 123.456.789.42

### **Blocked IPs**

Lists of **IPs** that must be **blocked** from the forwarders' answers. **V4 and V6** lists are **separated**.

[SET] dnsblrsd:blocked_ips_v4:*[DAEMON_ID]*

+ 123.456.789.42
+ 123.456.789.43

[SET] dnsblrsd:blocked_ips_v6:*[DAEMON_ID]*

+ ::42
+ ::43

## **Setup**

Firstly, a **Redis** database must be **installed** and  **setup** as shown above.

Then, **place** the provided `dnsblrsd.service` **file into** the `/etc/systemd/system` **directory**.

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

+ **Modify** the **environment variable** `TOKIO_WORKER_THREADS` through the **service file** to **define** the **number of threads** the runtime has to **use**. The **optimum number of threads relies on what is choking performance**. **High I/O latency** will **require more threads** to **keep** the **system busy**, otherwise some threads would remain idle while waiting on I/O. Try to **find** the **sweet spot** for your system and network. ***This massively improves performance***.

### **DO NOT**

+ **Use** a **superuser** to **run** the **server**. **Create** a new **user** with **limited privileges** to run the server with. Even though this server's stability was thoroughly checked via fuzzing, running the server on **elevated privileges** would **allow** an **unforeseen vulnerability** to **wreak havoc** on the system. A new **limited user** would **restrain** an **intruder** to the **limited privileges** unless escalation is possible.

# **Redis-ctl**

This is a command-line tool used to modify the blacklist stored in the Redis database.

```
Usage: redis-ctl <PATH_TO_CONFILE> <COMMAND>

Commands:
  conf   Display the dnslrd configuration
  get    Get info about a matchclass
  set    Add a new rule
  del    Delete a rule or a complete matchclass
  drop   Drop all matchclasses that match a pattern
  feed   Feed a list of domains to a matchclass
  stats  Display stats about IP addresses that match a pattern
  clear  Clear stats about IP addresses that match a pattern
  help   Print this message or the help of the given subcommand(s)

Arguments:
  <PATH_TO_CONFILE>  Path to dnsblrsd.conf is required

Options:
  -h, --help  Print help
```

## **conf**

``` 
Usage: redis-ctl <PATH_TO_CONFILE> showconf
```

**Displays** the daemon's **configuration**.

This command fetches the configuration that the daemon uses.

## **get**

``` 
Usage: redis-ctl <PATH_TO_CONFILE> get <MATCHCLASS>
```

**Retrieves** all the **information** of a **matchclass**.

## **set**

``` 
Usage: redis-ctl <PATH_TO_CONFILE> set <MATCHCLASS> [QTYPE [IP]]
```

**Adds** a new **rule** to the **blacklist**.

+ Example 1: add rule with default ipv6

  `[..] set malware#BLAZIT420:not.honey.pot.net. AAAA`

+ Example 2: add rule with custom ipv4

  `[..] set adult#PEG69:daddyissues.com. A 127.0.0.1`

## **del**

``` 
Usage: redis-ctl <PATH_TO_CONFILE> del <MATCHCLASS> [QTYPE]
```

**Deletes** a **matchclass or** one of its two **rules**.

+ Example 1: delete the complete matchclass

  `[..] del malware#ICU2:surely.notpwned.net.`

+ Example 2: delete ipv6 rule of matchclass

  `[..] del malware#ICU2:surely.notpwned.net. AAAA`

## **drop**

```
Usage: redis-ctl <PATH_TO_CONFILE> drop <PATTERN>
```

**Deletes** all **matchclasses** that match a **pattern**.

Redis' **wildcards** (*?) can be used on the pattern.

+ Example:

  `[..] drop malware#ID?????:*`

## **feed**

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

## **stats**

```
Usage: redis-ctl <PATH_TO_CONFILE> stats <PATTERN>
```

**Displays** all **stats** that match an IP **pattern**.

Redis' **wildcards** (*?) can be used on the pattern.

+ Example:

  `[..] stats 123.?.??.*`

## **Clear**
```
Usage: redis-ctl <PATH_TO_CONFILE> clear <PATTERN>
```

**Deletes** all **stats** that match an **IP pattern**.

Redis' **wildcards** (*?) can be used on the pattern.

+ Example:

  `[..] clear 123.?.??.*`
