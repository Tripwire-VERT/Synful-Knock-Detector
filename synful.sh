#!/bin/bash
#
# Shell Script to Detect Synful Knock written by Tripwire VERT
# Based on FireEye nping details @ https://www.fireeye.com/blog/threat-research/2015/09/synful_knock_-_acis0.html

RESULT=$(sudo nping -c1 -v3 --tcp -p 80 --seq 791104 --ack 3 "$1")
if [ $(echo "$RESULT" | wc -c | tr -d ' ') -eq 1 ] 
    then 
        echo "No Host Response" 
        exit 1
elif [ $(echo "$RESULT" | grep 'RCVD' | wc -c | tr -d ' ') -eq 0 ]; 
    then 
        echo "No Data Received"
        exit 1
fi
SEQ=$(echo "$RESULT" | grep RCVD | cut -d' ' -f8 | cut -d'=' -f2)
ACK=$(echo "$RESULT" | grep RCVD| cut -d' ' -f9 | cut -d'=' -f2)
OPTIONS=$(echo "$RESULT" | grep -A100 'RCVD' | grep -E '00[0-9]0' | cut -d' ' -f4-20 | awk '{$1=$1}{ print}' | sed 's/^/ /' | tr -d '\n')
DIFF=$(expr $ACK - $SEQ)
if [ $DIFF -eq 791102 ] 
    then
        if [ "$(echo "$OPTIONS" | grep '02 04 05 b4 01 01 04 02 01 03 03 05' | wc -c)" -gt 1 ]
            then
                echo "AFFECTED"
                exit 1 
        fi
fi  
echo "NOT AFFECTED" 


