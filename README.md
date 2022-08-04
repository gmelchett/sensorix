# sensorix

There are tons of different kinds of monitoring programs. I just want to have
a simple health monitor that can alert me when my little toy cluster need some
attention. No graphs, no fancy dashboard.
`sensorix` is there just to give a hands up that attention is needed.

## What to monitor:
  * Temperature getting too high
  * Running out of disk space
  * Process using 100% of a CPU core for a longer period
  * Running out of RAM
  * Running out of Swap (Probably not happen when there is RAM..)
  * Ping other members of the cluster
  * Run "lxc cluster list" and check status of all cluster members

## TODO:
  * Count amount of data written disks

## How to ask for attension:
  * Mail via smtp
  * gotify

I would be happy with only `gotify`, but that cluster member might be down. Therefore alerts are
send via mail as well.

## Building
`go get -u && CGO_ENABLED=0 go build` and copy the statically linked `sensorix` binary to your servers.

## Configuration
See `sensorix.conf`


## Running
No special access rights are needed. However running `sensorix` inside a container won't make much sense.
Give the full path to your `sensorix.conf` file as argument

# License
MIT
