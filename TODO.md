# todo

- restructure redis database to allow matchclasses to be disabled without removing them

- acquiring rules and IPs to block with a cron
- hardening                             ==> new user & nftables & SELinux
- remove unnecessary services
- shield with dnsdist                   ==> rate limiting & eBPF kernel filtering
- limits

## dnslrd
- remove ugly code

- HTTPS handling
- matchclass counter
- find optimum number of threads to ease IO bottleneck
- add windows signal and build option

## redis-ctl

- add clarity to optional values?