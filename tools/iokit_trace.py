# Resume las peticiones IOKit por proceso a partir del registro de tahoe-run.
# Uso: touch /dev/shm/tahoe-iokit-trace (activa la traza), arrancar launchd con TAHOE_LOGFILE=~/.claude-tmp/child.log, y luego:
#   python3 tools/iokit_trace.py [líneas por proceso]
import re,collections,sys
names={}
log=open('/home/eduardo/.claude-tmp/child.log',errors='replace').read().splitlines()
for l in log:
    m=re.search(r'<(\d+)> cargado (\S+)',l)
    if m and m.group(2)!='dyld': names[m.group(1)]=m.group(2)
c=collections.OrderedDict()
for l in log:
    m=re.search(r'IOKIT <(\d+)> (.*)',l)
    if m:
        k=(names.get(m.group(1),m.group(1)),re.sub(r'0x[0-9a-f]{5,}','N',m.group(2)))
        c[k]=c.get(k,0)+1
by=collections.defaultdict(list)
for (p,r),n in c.items(): by[p].append((r,n))
for p,l in by.items():
    print('==',p,len(l))
    for r,n in l[:int(sys.argv[1]) if len(sys.argv)>1 else 60]: print('  ',n,r[:230])
