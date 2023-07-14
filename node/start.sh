#!/bin/bash

cd bandwidth
for i in $(seq 0 3)
do
:> result$i
done

cd ../result
for i in $(seq 0 3)
do
:> result$i
done

cd ..
for i in $(seq 0 3)
do
./node $i > result/result$i &
echo "consensus node $i is running"
port=3000$i
PID=$(sudo netstat -nlp | grep "$port" | awk '{print $7}' | awk -F '[ / ]' '{print $1}')
echo ${PID} >> result/running.pid
done

wait
echo "all nodes are closed"