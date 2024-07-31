# dnslrd

- make separate functions for signals and main config builds -> build function and init function
- resolver is currently not rebuilt when configuration changes
- ArcSwap is misused in combination of Arc

- change term blackholes -> sinks

- implement EDE (Extended DNS Errors)

- graceful shutdown

# redis-ctl

- check if ctl tool needs updating to work with new dnsblrsd

- add help text to subcommands usage

- investigate Box<[u8]> to reduce memory usage of auto_feed

- investigate ahash to speed up hashing of sets
