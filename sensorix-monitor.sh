#!/bin/bash
#set -e

STAT_CURR=`nc localhost 5678 2> /dev/null`

if [ $? == 1 ]; then
    echo "sensorix isn't up and running!"
    exit 1
fi

TEMP_FILE=/tmp/.sensorix.status
if [ -f $TEMP_FILE ]; then
    STAT_OLD=`cat $TEMP_FILE`
    if [ "$STAT_OLD" == "$STAT_CURR" ]; then
	echo "sensorix is stuck: $STAT_OLD"
	exit 1
    fi
fi
echo $STAT_CURR > $TEMP_FILE
