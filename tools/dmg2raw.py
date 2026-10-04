import sys,struct,plistlib,zlib,bz2,base64
src,dst=sys.argv[1:3]
f=open(src,'rb'); f.seek(-512,2); k=f.read(512)
assert k[:4]==b'koly'
xoff,xlen=struct.unpack('>QQ',k[216:232])
f.seek(xoff); pl=plistlib.loads(f.read(xlen))
out=open(dst,'wb')
for blk in pl['resource-fork']['blkx']:
    d=blk['Data']
    assert d[:4]==b'mish'
    sec0,nsec=struct.unpack('>QQ',d[8:24]); dataoff=struct.unpack('>Q',d[24:32])[0]; n=struct.unpack('>I',d[200:204])[0]
    for i in range(n):
        e=d[204+i*40:244+i*40]
        t,_,so,sc,co,cl=struct.unpack('>IIQQQQ',e)
        if t==0xffffffff: break
        out.seek((sec0+so)*512)
        if t in(0,2): out.write(b'\0'*(sc*512)) if t==0 else None
        elif t==1: f.seek(dataoff+co); out.write(f.read(cl))
        elif t==0x80000005: f.seek(dataoff+co); out.write(zlib.decompress(f.read(cl)))
        elif t==0x80000006: f.seek(dataoff+co); out.write(bz2.decompress(f.read(cl)))
        elif t==0x7ffffffe: pass
        else: print("tipo no soportado",hex(t)); sys.exit(1)
out.truncate(max(out.tell(),0)); out.close()
