- check if there's another way to not sort records of resolver
- make dns client per forwarder and run in own thread/task
- rethink and implement features
- make redis-manager run in own thread/task
-> ultimately remove Redis dependency

# dnslrd

- graceful shutdown

# redis-ctl

- add possiblity that TTL will simply be an int instead of "1d","1m","1y" 
