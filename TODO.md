# For both

- add possibility that retention time could simply be "3m"

Possible future improvements:
- remove Redis dependency
- remove hickory_dns dependency
- live full configuration reload without dropping requests

# dnsblrsd

- graceful shutdown
- implement commented features
- make resolver per forwarder and run in own thread/task

# redis-ctl

- add possiblity that TTL will simply be an int instead of "1d","1m","1y"
