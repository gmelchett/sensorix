# sensorix

There are tons of different kinds of monitoring programs. I just want to have
a simple health monitor that can alert me when my little toy cluster need some
attention. No graphs, no fancy dashboard.
`sensorix` is there just to give a hands up that attention is needed.


## What sensorix monitors:
  * Temperature
  * Free disk space
  * CPU usage
  * RAM usage
  * Swap usage (Probably not happen when there is RAM..)
  * Pong from other hosts
  * "lxc cluster list" status of all cluster members


## How `sensorix` alerts:
  * Mail via SMTP
  * [gotify](https://gotify.net/)

I think I would be happy with only `gotify`, but that cluster member might be down. Therefore
alerts are send via mail as well.


## Building:
`go get -u && CGO_ENABLED=0 go build` and copy the statically linked `sensorix` binary to your servers.


## Configuration
See `sensorix.conf`


## TODO:
  * Count amount of data written disks
  * smartmon?


## Running
No special access rights are needed. However running `sensorix` inside a container won't make much sense.

By default `sensorix` looks a `sensorix.conf` in the current working directory. Valid options are:
```
Usage of ./sensorix:
  -c string
        Configuration file. (default "sensorix.conf")
  -g    Send a test gotify message.
  -m    Send a test mail.
```

### Alpine Linux
Copy `sensorix-start` to `/etc/init.d/` and `sensorix-start` to suit your username and path.

```
doas mkdir /var/log/sensorix
doas chown jonas:jonas /var/log/sensorix

doas rc-update add sensorix-start default
doas rc-service sensorix-start start
```

# License
MIT
