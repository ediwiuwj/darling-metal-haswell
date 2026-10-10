#!/bin/bash
# Guardián de memoria para las pruebas: si la RAM disponible baja de 900 MB o el swap usado supera 1.5 GB, mata todo tahoe-run.
# Parar con: touch /dev/shm/tahoe-guard-stop
while [ ! -e /dev/shm/tahoe-guard-stop ]; do
  av=$(awk '/MemAvailable/{print int($2/1024)}' /proc/meminfo)
  sw=$(awk '/SwapTotal/{t=$2}/SwapFree/{f=$2}END{print int((t-f)/1024)}' /proc/meminfo)
  if [ "$av" -lt 900 ] || [ "$sw" -gt 1500 ]; then
    pkill -9 -x tahoe-run; pkill -9 unshare
    echo "guardian: disponible=${av}MB swap=${sw}MB -> procesos de tahoe-run terminados" >> ${TMPDIR:-/tmp}/tahoe-guard.log
  fi
  for p in $(pgrep -x tahoe-run); do a=$(awk '/RssAnon/{print int($2/1024)}' /proc/$p/status 2>/dev/null); if [ "${a:-0}" -gt 700 ]; then echo "guardián: pid $p anon=${a}MB -> terminado" >&2; pkill -9 -x tahoe-run; pkill -9 unshare; fi; done
  sleep 1
done
