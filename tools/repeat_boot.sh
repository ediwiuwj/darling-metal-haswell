#!/bin/bash
# Repite el arranque de launchd N veces (con ionice idle, como la condición que reveló la carrera de kqueue) y resume los procesos vivos.
cd ~/.claude-tmp
rm -f ticks2.out
for r in 1 2 3; do
  rm -f guard.log /dev/shm/tahoe-guard-stop /dev/shm/tahoe-ports* /dev/shm/tahoe.* /dev/shm/tahoe-hid*
  ./guard.sh &
  ( nice -n 15 ionice -c3 ./rl.sh 24 > rl.out 2>&1 & )
  sleep 12; a=$(pgrep -cx tahoe-run); sleep 8; b=$(pgrep -cx tahoe-run); sleep 8; c=$(pgrep -cx tahoe-run); sleep 8
  echo "run$r procs@12s=$a @20s=$b @28s=$c launchd_caido=$(grep -ac 'SIGSEGV <1>\|SIGILL <1>' child.log) aborts=$(grep -a 'SIGILL <\|SIGSEGV <' child.log | wc -l) guardian=$(cat guard.log 2>/dev/null | wc -l)" >> ticks2.out
  touch /dev/shm/tahoe-guard-stop; sleep 1.5; rm -f /dev/shm/tahoe-guard-stop
  pkill -9 -x tahoe-run; pkill -9 unshare; sleep 1
done
rm -f /dev/shm/tahoe.* /dev/shm/tahoe-ports* /dev/shm/tahoe-hid*
echo listo >> ticks2.out
