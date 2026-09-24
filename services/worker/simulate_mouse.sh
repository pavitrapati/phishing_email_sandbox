#!/bin/bash
# Wait for Xvfb to start
sleep 2

while true; do
    # Move mouse randomly
    xdotool mousemove_relative -- $((RANDOM % 50 - 25)) $((RANDOM % 50 - 25))
    
    # Randomly click
    if [ $((RANDOM % 10)) -lt 2 ]; then
        xdotool click 1
    fi
    
    # Randomly double click
    if [ $((RANDOM % 10)) -lt 1 ]; then
        xdotool click --repeat 2 1
    fi
    
    sleep 0.5
done
