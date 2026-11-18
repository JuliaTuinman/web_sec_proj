#!/usr/bin/env bash
# Benign-only traffic for MQM learn mode: exercises every endpoint with normal inputs.
B=${1:-http://localhost:3000}
j='-H Content-Type:application/json'
for u in alice bob carol; do
  curl -s -o /dev/null $j -d "{\"username\":\"$u\",\"password\":\"${u}123\"}" $B/login
  curl -s -o /dev/null "$B/profile?username=$u"
done
for q in Laptop Mouse Book; do curl -s -o /dev/null "$B/search?q=$q"; done
for c in books electronics toys; do curl -s -o /dev/null "$B/filter?category=$c&maxPrice=500"; done
echo "learn traffic sent"
