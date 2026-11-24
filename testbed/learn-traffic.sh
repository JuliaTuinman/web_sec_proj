#!/usr/bin/env bash
# Benign-only traffic for MQM learn mode. One generator for learning and for
# measuring, so a false positive can never be a difference between the two:
# this just calls eval/traffic.js (--fraction F for the coverage runs).
exec node "$(dirname "$0")/eval/traffic.js" benign --base "${1:-http://localhost:3000}" >/dev/null
