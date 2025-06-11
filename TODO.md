- make resolver per forwarder and run in own thread/task
- make it so in config is defined the binds along with the filters they'll have to serve
-> ultimately remove Redis dependency
- rethink and implement features

# dnslrd

- graceful shutdown

# redis-ctl

- add possiblity that TTL will simply be an int instead of "1d","1m","1y" 
