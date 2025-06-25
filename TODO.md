- make resolver per forwarder and run in own thread/task
-> ultimately remove Redis dependency

- add possibility that retention time could simply be "3m"

# dnsblrsd

- graceful shutdown
- rethink and implement features
- get rid of hickory_dns dependency -> add used service to logs for incoming requests

# redis-ctl

- add possiblity that TTL will simply be an int instead of "1d","1m","1y" 
