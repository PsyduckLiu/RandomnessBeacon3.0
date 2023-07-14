#!/bin/bash

cd result
cat running.pid | xargs -IX kill -9 X
:> running.pid

# for i in $(seq 0 3)
# do
# kill -9 `ps -ef |grep exe/main\ $i|awk '{print $2}'`
# done

ps -ef | grep start.sh | grep -v grep | awk '{print $2}' | xargs kill