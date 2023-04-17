# todo

- hardening                             ==> new user & nftables & SELinux
- remove unnecessary services
- shield with dnsdist                   ==> rate limiting & eBPF kernel filtering
- limits
- restart automatically on failure?

## dnslrd
- clear resolver cache on SIGUSR1       ==> water torture mitigation
- SIGUSR2 is_filtering switch?

- matchclass counter
- find optimum number of threads to ease IO bottleneck
- add windows signal and build option

- anyhow with context ?
- configure crate ?
- redis connection pool? (r2d2 ?)

## redis-ctl
- modify daemon's configuration with new commands

- add clarity to optional values?