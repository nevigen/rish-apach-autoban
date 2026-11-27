"""Load, validate and update the Apache AutoBan configuration."""

import os, sys, stat, re, tempfile, fcntl
P='/etc/apache-autoban'; NAME='config.conf'
DEFAULTS=dict(AUTOBAN_LANG='ru',MIN_REQUESTS='3',BAN_TIME='86400',ZONE='',AUTOBAN_STRICT_MATCH='0',LOG_DIR='/var/www',STOPWORDS='/root/apache-stopwords.txt',WHITELIST='/root/apache-whitelist.txt',BAN_LOG='/var/log/apache-autoban.log')
def validate(k,v):
    if k not in DEFAULTS or any(ord(c)<32 or ord(c)==127 for c in v): raise ValueError('Invalid config key/value: '+k)
    if k=='AUTOBAN_LANG': ok=v in ('ru','uk','en')
    elif k=='AUTOBAN_STRICT_MATCH': ok=v in ('0','1')
    elif k=='MIN_REQUESTS': ok=bool(re.fullmatch(r'[1-9][0-9]{0,5}',v))
    elif k=='BAN_TIME': ok=bool(re.fullmatch(r'[1-9][0-9]{0,7}',v)) and int(v)<=31536000
    elif k=='ZONE': ok=not v or bool(re.fullmatch(r'[A-Za-z0-9_.-]+',v))
    else: ok=v.startswith('/')
    if not ok: raise ValueError('Invalid config value: '+k)
    return v
def check(s, directory=False):
    if s.st_uid!=0 or s.st_mode & 0o022 or not (stat.S_ISDIR(s.st_mode) if directory else stat.S_ISREG(s.st_mode)) or (not directory and s.st_nlink!=1): raise ValueError('Unsafe config path')
def read(d, with_lines=False):
    try: fd=os.open(NAME,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=d)
    except FileNotFoundError: return ({}, []) if with_lines else {}
    with os.fdopen(fd,encoding='utf-8') as f:
        check(os.fstat(f.fileno())); data={}
        lines=f.readlines()
        for line in lines:
            line=line.strip()
            if not line or line.startswith('#'): continue
            k,sep,v=line.partition('=')
            if not sep or k not in DEFAULTS: raise ValueError('Unknown config key: '+k)
            if len(v)>=2 and v[0]==v[-1] and v[0] in "\"'": v=v[1:-1]
            data[k]=validate(k,v)
        return (data, lines) if with_lines else data
def main():
    if sys.argv[1]=='validate': validate(*sys.argv[2:]); return
    d=os.open('/etc',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW); check(os.fstat(d),True)
    try: sub=os.open('apache-autoban',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=d)
    finally: os.close(d)
    try:
        check(os.fstat(sub),True)
        if sys.argv[1]=='load':
            values=DEFAULTS | read(sub)
            for k,v in values.items(): print(k+'='+validate(k,os.environ.get(k,v)))
        elif sys.argv[1]=='set':
            k,v=sys.argv[2:]; validate(k,v)
            lock=os.open('.lock',os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW|os.O_NONBLOCK,0o600,dir_fd=sub)
            try:
                check(os.fstat(lock)); fcntl.flock(lock,fcntl.LOCK_EX)
                values,lines=read(sub,with_lines=True)
                # Preserve comments, blank lines and unrelated settings; collapse duplicate target keys.
                updated=[]; written=False
                for line in lines:
                    if line.strip().partition('=')[0]==k:
                        if not written: updated.append(k+'='+v+'\n'); written=True
                    else: updated.append(line)
                if not written:
                    if updated and not updated[-1].endswith('\n'): updated[-1]+='\n'
                    updated.append(k+'='+v+'\n')
                fd,name=tempfile.mkstemp(prefix='.config.',dir=P)
                try:
                    with os.fdopen(fd,'w',encoding='utf-8') as f:
                        os.fchmod(f.fileno(),0o600)
                        f.writelines(updated); f.flush(); os.fsync(f.fileno())
                    os.replace(os.path.basename(name),NAME,src_dir_fd=sub,dst_dir_fd=sub); os.fsync(sub)
                finally:
                    try: os.unlink(os.path.basename(name),dir_fd=sub)
                    except FileNotFoundError: pass
            finally: os.close(lock)
    finally: os.close(sub)
if __name__=='__main__':
    try: main()
    except (OSError,ValueError) as e: sys.exit(str(e))
