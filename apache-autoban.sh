#!/usr/bin/env bash
# RISH Apache AutoBan v1.0.1
set -euo pipefail
umask 077
export LC_ALL=C

die() { echo "$*" >&2; exit 1; }

[[ $EUID == 0 ]] || die 'Run as root'
BASE=$(dirname -- "$(readlink -f -- "${BASH_SOURCE[0]}")")
source "$BASE/config.sh"
load_config || die 'Invalid configuration'
LOCK_WAIT=${AUTOBAN_LOCK_WAIT:-60}
[[ $LOCK_WAIT =~ ^[0-9]{1,4}$ ]] || die 'Invalid AUTOBAN_LOCK_WAIT'

BASE=$(dirname -- "$(readlink -f -- "${BASH_SOURCE[0]}")")
export LOG_DIR STOPWORDS WHITELIST BAN_LOG BAN_TIME MIN_REQUESTS ZONE AUTOBAN_LANG
export AUTOBAN_BASE="$BASE"

if [[ $# -eq 0 ]]; then
    [[ -t 0 ]] || die "Use --dry-run or --ban (interactive menu needs a terminal)"
    exec "$BASE/menu.sh"
fi

MODE=$1
USAGE="Usage: $0 [--dry-run|--ban|--top-ip|--top-sites|--top-urls] [date prefix[,prefix...] | --last 1h | --from ISO --to ISO] | --list | --clear-bans | --unban IP | --manual-ban IP | --inspect IP"
case "$MODE" in
    --dry-run|--ban|--top-ip|--top-sites|--top-urls|--list|--clear-bans) ;;
    --unban|--manual-ban|--inspect) [[ -n ${2:-} ]] || die "$USAGE" ;;
    *) die "$USAGE" ;;
esac

# Without an explicit period only the live logs (plus rotated files touched in the
# last 3 hours) are read. An explicit period also reads rotated and .gz logs.
ROTATED=0
case "$MODE" in
    --dry-run|--ban|--top-ip|--top-sites|--top-urls)
        if [[ ${2:-} == --last && $# == 3 ]]; then
            DATE_FILTER="last:$3"; ROTATED=1
        elif [[ ${2:-} == --from && $# == 5 && $4 == --to ]]; then
            DATE_FILTER="range:$3,$5"; ROTATED=1
        elif [[ -n ${2:-} ]]; then
            DATE_FILTER=$2; ROTATED=1
        else
            DATE_FILTER=''
        fi ;;
    *) DATE_FILTER=${2:-} ;;   # IP address for --unban / --manual-ban / --inspect
esac

[[ $EUID == 0 ]] || die 'Run as root'
command -v python3 >/dev/null || die 'python3 is required'
exec 9>/run/apache-autoban.lock
flock -w "$LOCK_WAIT" 9 || { echo "Another AutoBan operation is running (waited ${LOCK_WAIT}s)." >&2; exit 75; }
[[ -f "$BASE/apache-autoban.sh" ]] || die 'Apache AutoBan was removed while waiting to start'

AUTOBAN_ROTATED=$ROTATED python3 -u - "$LOG_DIR" "$STOPWORDS" "$WHITELIST" "$DATE_FILTER" "$MIN_REQUESTS" "$MODE" "$ZONE" "$BAN_TIME" "$BAN_LOG" <<'PY'
import sys, pathlib, ipaddress, re, collections, subprocess, datetime, json, os, gzip, time, zlib, stat, hashlib, tempfile, errno
from functools import lru_cache
from urllib.parse import unquote

root, stop, white, prefix, minimum, mode, zone, duration, logfile = sys.argv[1:]
minimum = int(minimum)
started_at = time.monotonic()
rotated_ok = os.environ.get('AUTOBAN_ROTATED') == '1'
strict_match = os.environ.get('AUTOBAN_STRICT_MATCH') == '1'
RECENT_SECONDS = 3 * 3600
registry = pathlib.Path('/var/lib/apache-autoban/rish-bans.json')
lang = os.environ.get('AUTOBAN_LANG', 'ru')
if lang not in ('ru', 'uk', 'en'): lang = 'en'
try:
    translations = json.loads((pathlib.Path(os.environ['AUTOBAN_BASE']) / 'lang' / (lang + '.json')).read_text(encoding='utf-8'))
except (OSError, KeyError, ValueError):
    translations = {}
def tr(s): return translations.get(s, s)

# Presentation only: never store ANSI sequences in logs or cache.
import builtins

def paint(value, color, stream=None):
    stream = sys.stdout if stream is None else stream
    if (stream.isatty() and os.environ.get('TERM', '') not in ('', 'dumb')
            and 'NO_COLOR' not in os.environ):
        return f'\x1b[{color}m{value}\x1b[0m'
    return str(value)

def show(*args, color='36', **kwargs):
    stream = kwargs.get('file') or sys.stdout
    builtins.print(paint(' '.join(map(str, args)), color, stream), **kwargs)

STATUS_COLOR = {'BANNED':'32', 'ALREADY-BANNED':'33', 'BANNING':'36',
                'DRY-RUN':'94', 'ERROR':'31', 'QUERY-ERROR':'31',
                'UNKNOWN-FIREWALL':'33', 'UNBANNED':'32'}


# ---------- firewalld helpers ----------
def fw(*args):
    try: return subprocess.run(['firewall-cmd', *args], capture_output=True, text=True)
    except OSError: return None
def ok(r): return r is not None and r.returncode == 0
def require(r):
    if not ok(r): sys.exit('firewalld error: ' + (r.stderr.strip() if r else 'unavailable'))
    return r.stdout.strip()
def parse_ip(value):
    try: return ipaddress.ip_address(value.strip())
    except ValueError: sys.exit(f'Invalid IP address: {value!r}')
def resolve_zone():
    global zone
    if zone: return zone
    r = fw('--get-active-zones')
    if not ok(r): return ''
    zones = [x.split()[0] for x in r.stdout.splitlines() if x and not x[0].isspace()]
    if len(zones) == 1: zone = zones[0]
    return zone
def rule(ip): return f'rule priority="-110" family="ipv{ip.version}" source address="{ip}/{ip.max_prefixlen}" drop'
RULE_RE = re.compile(r'rule (?:priority="-?\d+" )?family="ipv[46]" source address="([^"]+)" drop')
# One snapshot per scan. RISH still performs its own authoritative checks.
_rule_cache = {}
def rules_snapshot(z, refresh=False):
    if refresh or z not in _rule_cache:
        r = fw('--zone=' + z, '--list-rich-rules')
        nets = []
        if ok(r):
            for line in r.stdout.splitlines():
                m = RULE_RE.fullmatch(line.strip())
                if m:
                    try: nets.append((ipaddress.ip_network(m[1], strict=False), line.strip()))
                    except ValueError: pass
        _rule_cache[z] = (nets, r)
    return _rule_cache[z]
def find_rule(ip, z, refresh=False):
    nets, r = rules_snapshot(z, refresh)
    if not ok(r): return None, r
    for net, line in nets:
        if ip.version == net.version and ip in net: return line, r
    return '', r
def query(ip, z):
    line, r = find_rule(ip, z)
    if line is None: return r
    return subprocess.CompletedProcess([], 0 if line else 1, 'yes' if line else 'no', '')
def native_query(ip, z): return fw('--zone=' + z, '--query-rich-rule=' + rule(ip))
def bridge(action, ip):
    try:
        return subprocess.run([os.path.join(os.environ['AUTOBAN_BASE'], 'rish-bridge.sh'), action, zone, str(ip), duration],
                              capture_output=True, text=True)
    except OSError as e:
        return subprocess.CompletedProcess([], 127, '', str(e))
def ledger():
    p = pathlib.Path('/run/rish/firewall/temporary.tsv')
    out = {}
    try: lines = p.read_text(encoding='utf-8').splitlines() if p.exists() else []
    except OSError: lines = []
    for line in lines:
        fields = line.split('\t', 3)
        if len(fields) == 4:
            try: out[(fields[1], str(ipaddress.ip_network(fields[0]).network_address))] = (int(fields[2]), fields[3])
            except ValueError: continue
    return out

# ---------- state ----------
def log(status, ip, count=0, reason='manual'):
    msg = f'{datetime.datetime.now().astimezone().isoformat()} | {status} | {ip} | {count} | {reason}'
    show(msg, color=STATUS_COLOR.get(status, "36"), flush=True)
    with open(logfile, 'a', encoding='utf-8') as f: f.write(msg + '\n')
def load():
    if not registry.exists(): return {}
    try: return json.loads(registry.read_text(encoding='utf-8'))
    except (OSError, ValueError):
        print(f'WARNING: {registry} is unreadable; treating it as empty', file=sys.stderr)
        return {}
def save(data):
    now = time.time()
    data = {k: v for k, v in data.items() if isinstance(v, (int, float)) and v > now}   # prune expired entries
    registry.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    tmp = registry.with_suffix('.tmp'); tmp.write_text(json.dumps(data), encoding='utf-8'); tmp.chmod(0o600); tmp.replace(registry)

# ---------- whitelist / stopwords ----------
WL_FILES = [pathlib.Path(white), pathlib.Path('/etc/firewalld/rish-whitelist.txt')]
def whitelist():
    out = []
    for p in WL_FILES:
        if not p.exists():
            if p == WL_FILES[0]: sys.exit(f'Whitelist file not found: {p}')
            continue
        for n, line in enumerate(p.read_text(encoding='utf-8', errors='replace').splitlines(), 1):
            entry = line.split('#', 1)[0].strip()
            if not entry: continue
            try: out.append(ipaddress.ip_network(entry, strict=False))
            except ValueError: sys.exit(f'Bad whitelist entry in {p}, line {n}: {entry!r}')
    return out
def excluded(ip, allow): return not ip.is_global or ip.is_multicast or any(ip.version == n.version and ip in n for n in allow)
def load_words():
    raw = []
    for line in pathlib.Path(stop).read_text(encoding='utf-8', errors='replace').splitlines():
        w = line.strip().lower()
        if w and not line.lstrip().startswith('#'): raw.append(w)
    raw = list(dict.fromkeys(raw))
    for w in raw:
        if len(w) < 4: print(f'WARNING: stopword {w!r} is shorter than 4 characters and was ignored', file=sys.stderr)
    words = [w for w in raw if len(w) >= 4]
    if not words:
        sys.exit(f'No usable stopwords in {stop}: every line is commented out, empty or shorter than 4 characters. '
                 'Uncomment or add words (menu item 7).')
    return words
def decode(s):
    # Undo percent-encoding up to 3 layers deep (catches %252e style evasion).
    for _ in range(3):
        n = unquote(s)
        if n == s: break
        s = n
    return s

# ---------- ban ----------
def ban(ip, count, reason):
    q = query(ip, zone)
    if ok(q): show(f'ALREADY-BANNED | {ip}', color='33'); return 'ALREADY-BANNED'
    if q is None or q.returncode != 1: show(f'QUERY-ERROR | {ip}', color='31'); return 'ERROR'
    data = load()
    show(f'BANNING | {ip} | {tr("Calling RISH")}', flush=True)
    bridge_started = time.monotonic()
    r = bridge('add', ip)
    show(f'RISH | {ip} | {tr("RISH call time (s)")}: {time.monotonic()-bridge_started:.3f}', flush=True)
    if not ok(r):
        out = ' '.join((r.stderr + ' ' + r.stdout).split())
        if 'постоянный список RISH' in out:
            show(f'ALREADY-BANNED | {ip} (RISH permanent list)', color='33'); return 'ALREADY-BANNED'
        show(f'ERROR | {ip} | {out}', color='31'); return 'ERROR'
    verify_started = time.monotonic()
    entry = ledger().get((zone, str(ip)))
    confirmed = bool(entry and ok(native_query(ip, zone)))
    show(f'{ip} | {tr("Verification time (s)")}: {time.monotonic()-verify_started:.3f}', flush=True)
    if not confirmed:
        show(f'ERROR | {ip} | RISH ledger or live rule not confirmed', color='31'); return 'ERROR'
    _rule_cache[zone][0].append((ipaddress.ip_network(str(ip)), rule(ip)))
    data[zone + '|' + str(ip)] = entry[0]
    save(data); log('BANNED', ip, count, reason); return 'BANNED'

if mode in ('--ban', '--manual-ban', '--list', '--unban', '--clear-bans'):
    if not resolve_zone(): sys.exit('Set ZONE explicitly (config.conf or menu item 19): no unique active firewalld zone')
    require(fw('--state'))
    if mode in ('--ban', '--manual-ban') and not (os.environ.get('SSH_CONNECTION') or os.environ.get('SSH_CLIENT')):
        sys.exit('RISH requires a real SSH context (run from a root SSH session; sudo usually drops SSH_CONNECTION). '
                 'Use --dry-run in cron; no rules changed.')

if mode == '--list':
    d = fw('--get-default-zone'); dz = d.stdout.strip() if ok(d) else '?'
    print('Zone:', zone, f'(firewalld default zone: {dz})')
    if dz not in ('?', zone): print('Note: the RISH menu works with the default zone; AutoBan uses', zone)
    print(require(fw('--zone=' + zone, '--list-rich-rules'))); sys.exit(0)

if mode == '--manual-ban':
    ip = parse_ip(prefix)
    if excluded(ip, whitelist()): sys.exit('IP excluded by safety checks / whitelist')
    sys.exit(1 if ban(ip, 0, 'manual') == 'ERROR' else 0)

if mode in ('--unban', '--clear-bans'):
    data = load(); now = time.time()
    if mode == '--unban': targets = [parse_ip(prefix)]
    else: targets = [ipaddress.ip_address(k.split('|', 1)[1]) for k, v in data.items() if k.startswith(zone + '|') and v > now]
    errors = legacy = 0
    for ip in targets:
        key = zone + '|' + str(ip)
        entry = ledger().get((zone, str(ip)))
        if mode == '--clear-bans' and (not entry or entry[0] != data.get(key)):
            print('SKIPPED (ownership/expiry not confirmed)', ip); continue
        if entry and ok(native_query(ip, zone)):
            r = bridge('remove', ip)
            if not ok(r) or ok(native_query(ip, zone)):
                errors += 1; print('ERROR', ip, r.stderr, r.stdout); continue
            log('UNBANNED', ip); data.pop(key, None)
            continue
        line, _ = find_rule(ip, zone, refresh=True)
        if line is None:
            errors += 1; print('ERROR', ip, 'cannot read firewalld rules'); continue
        if line:
            legacy += 1
            print(f'NOT-MANAGED {ip}: a live rule exists but is not registered by RISH (legacy ban). Remove it manually:')
            print(f"  firewall-cmd --zone={zone} --remove-rich-rule='{line}'")
        else:
            data.pop(key, None); print('NOT-BANNED', ip)
    save(data); print('Errors:', errors)
    sys.exit(1 if errors else 3 if legacy else 0)

if mode not in ('--dry-run', '--ban', '--inspect', '--top-ip', '--top-sites', '--top-urls'): sys.exit('Unknown mode')
inspect = parse_ip(prefix) if mode == '--inspect' else None
hour_format = '%d/%b/%Y:%H:'
now = datetime.datetime.now(datetime.timezone.utc)
live_hours = tuple((now - datetime.timedelta(hours=h)).astimezone().strftime(hour_format) for h in (1, 0))
if not prefix or inspect is not None:
    prefix = ','.join(live_hours)
prefixes = tuple(p.strip() for p in prefix.split(',') if p.strip())
if not prefixes: sys.exit('Empty date filter')
interval = None
if prefix.startswith('last:'):
    spec = re.fullmatch(r'([1-9][0-9]{0,5})([mhd])', prefix[5:])
    if not spec: sys.exit('Invalid --last (example: 30m, 1h, 24h)')
    end = datetime.datetime.now(datetime.timezone.utc)
    seconds = int(spec[1]) * {'m':60,'h':3600,'d':86400}[spec[2]]
    if seconds > 31536000: sys.exit('--last maximum is 365 days')
    interval = (end-datetime.timedelta(seconds=seconds), end)
elif prefix.startswith('range:'):
    try:
        start,end = (datetime.datetime.fromisoformat(v.replace('Z','+00:00')) for v in prefix[6:].split(','))
        if start.tzinfo is None or end.tzinfo is None or start >= end: raise ValueError()
        interval = (start,end)
    except ValueError: sys.exit('Use ISO timestamps with timezone; start must precede end')
def in_period(value):
    if interval is None: return value.startswith(prefixes)
    try: stamp = datetime.datetime.strptime(value, '%d/%b/%Y:%H:%M:%S %z')
    except ValueError: return False
    return interval[0] <= stamp < interval[1]

words = []; allow = []
if mode in ('--dry-run', '--ban', '--top-urls'):
    words = load_words()
    allow = whitelist()

absolute_target = re.compile(r'^https?://[^/]+', re.IGNORECASE)
strict_words = [(word, re.compile(
    ('' if word.startswith('/') else r'(?:^|/)') + re.escape(word)
    + ('' if word.endswith('/') else r'(?=$|[/._-])')
)) for word in words] if strict_match else []

def match_target(target):
    if strict_match:
        target = re.split(r'[?#]', target, maxsplit=1)[0]
        # Only an absolute-form request target starts with a scheme and authority.
        target = absolute_target.sub('', target, count=1) or '/'
    raw = target.lower()
    decoded = decode(raw).lower()
    if strict_match:
        return raw, [word for word, pattern in strict_words if pattern.search(raw) or pattern.search(decoded)]
    return raw, [word for word in words if word in raw or word in decoded]

counts = collections.Counter(); domains = collections.Counter(); reasons = collections.defaultdict(collections.Counter)
allips = collections.Counter(); ipdomains = collections.defaultdict(collections.Counter); allsites = collections.Counter()
urls = collections.Counter(); statuses = collections.Counter()
files = requests = skipped = malformed = unreadable = unsafe = disappeared = oversized = 0
MAX_LINE = 256 * 1024
pattern = re.compile(r'^(?:\S+ )?(\S+) \S+ \S+ \[([^\]]+)\] "\S+ (\S+)')
ROT_RE = re.compile(r'-access-log(?:[.-]\d+)?(?:\.gz)?$')

# Never follow user-controlled symlinks, including intermediate directories.
DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
FILE_FLAGS = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC

class UnsafeLog(Exception): pass
class DisappearedLog(Exception): pass

def open_log(path):
    # Classify only discovery/open errors here, never actual read errors.
    try:
        rootfd = os.open(root, DIR_FLAGS)
    except OSError:
        raise  # configured root is an administrator-controlled dependency
    try:
        try:
            userfd = os.open(path.parent.parent.name, DIR_FLAGS, dir_fd=rootfd)
            try:
                logfd = os.open('logs', DIR_FLAGS, dir_fd=userfd)
                try:
                    before = os.stat(path.name, dir_fd=logfd, follow_symlinks=False)
                    if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
                        raise UnsafeLog('not a regular single-link log')
                    fd = os.open(path.name, FILE_FLAGS, dir_fd=logfd)
                finally: os.close(logfd)
            finally: os.close(userfd)
        except OSError as e:
            if e.errno in (errno.ELOOP, errno.ENOTDIR): raise UnsafeLog(str(e)) from e
            if e.errno == errno.ENOENT: raise DisappearedLog(str(e)) from e
            # A socket/device may have replaced the regular file during open.
            if e.errno in (errno.ENXIO, errno.ENODEV, errno.EISDIR): raise UnsafeLog(str(e)) from e
            raise
    finally: os.close(rootfd)
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1:
            raise UnsafeLog('not a regular single-link log')
        if (st.st_dev, st.st_ino) != (before.st_dev, before.st_ino):
            raise DisappearedLog('file replaced during open')
        return os.fdopen(fd, 'rb'), st
    except BaseException:
        os.close(fd); raise

def discover():
    global unsafe, disappeared, unreadable
    rootfd = os.open(root, DIR_FLAGS)
    try:
        for user in sorted(os.listdir(rootfd)):
            userpath = pathlib.Path(root) / user
            try:
                ust = os.stat(user, dir_fd=rootfd, follow_symlinks=False)
                if stat.S_ISLNK(ust.st_mode):
                    unsafe += 1; print(f'WARNING: unsafe directory skipped: {str(userpath)!r}', file=sys.stderr); continue
                if not stat.S_ISDIR(ust.st_mode): continue
                ufd = os.open(user, DIR_FLAGS, dir_fd=rootfd)
                try:
                    try: lst = os.stat('logs', dir_fd=ufd, follow_symlinks=False)
                    except FileNotFoundError: continue  # ordinary user without logs
                    if not stat.S_ISDIR(lst.st_mode):
                        raise UnsafeLog('logs is not a real directory')
                    lfd = os.open('logs', DIR_FLAGS, dir_fd=ufd)
                    try: names = sorted(os.listdir(lfd))
                    finally: os.close(lfd)
                finally: os.close(ufd)
            except UnsafeLog as e:
                unsafe += 1; print(f'WARNING: unsafe directory skipped: {str(userpath)!r}: {str(e)!r}', file=sys.stderr); continue
            except OSError as e:
                if e.errno in (errno.ELOOP, errno.ENOTDIR): unsafe += 1
                elif e.errno == errno.ENOENT: disappeared += 1
                else: unreadable += 1
                print(f'WARNING: directory skipped: {str(userpath)!r}: {str(e)!r}', file=sys.stderr); continue
            for name in names:
                if ROT_RE.search(name): yield userpath / 'logs' / name
    finally: os.close(rootfd)

# The default window overlaps across scans. Keep its two hours separate so
# the previous hour's data can be reused when the window advances.
cache_enabled = mode in ('--dry-run', '--ban') and not prefix.startswith('last:')
hourly_cache = cache_enabled and not rotated_ok
cache_path = registry.parent / ('scan-history-v4.json' if rotated_ok else 'scan-cache-v4.json')
CACHE_LIMIT = 32 * 1024 * 1024
period_key = ['live-hours'] if hourly_cache else (
    ['range', *(dt.astimezone(datetime.timezone.utc).isoformat() for dt in interval)]
    if interval is not None else ['prefix', *prefixes])
cache_key = hashlib.sha256(json.dumps([str(pathlib.Path(root).absolute()), period_key, words,
    [str(n) for n in allow], strict_match], ensure_ascii=True).encode()).hexdigest()
old_cache = {}; new_cache = {}
if cache_enabled:
    try:
        cache_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        ds = cache_path.parent.stat()
        if cache_path.parent.is_symlink() or ds.st_uid != 0 or ds.st_mode & 0o077:
            raise OSError('unsafe cache directory')
        if cache_path.exists():
            cs = cache_path.lstat()
            if not stat.S_ISREG(cs.st_mode) or cs.st_uid != 0 or cs.st_mode & 0o077:
                raise OSError('unsafe cache file')
            if cs.st_size > CACHE_LIMIT: raise ValueError('cache size limit exceeded')
            with cache_path.open(encoding='utf-8') as cf: payload = json.load(cf)
            if payload.get('key') == cache_key and (
                not hourly_cache or payload.get('hour') in live_hours
            ):
                old_cache = payload['files']
    except (OSError, ValueError, KeyError, TypeError) as e:
        print('Cache unavailable:', str(e), file=sys.stderr); cache_enabled = False
hourly_cache = hourly_cache and cache_enabled


def restore_bucket(saved):
    return (collections.Counter({ipaddress.ip_address(ip): n for ip, n in saved['counts']}),
            collections.Counter({(ipaddress.ip_address(ip), word): n for ip, word, n in saved['reasons']}),
            list(saved['stats']))


def save_bucket(bucket):
    counts, reasons, stats = bucket
    return {'counts': [(str(ip), n) for ip, n in counts.items()],
            'reasons': [(str(ip), word, n) for (ip, word), n in reasons.items()], 'stats': stats}


def new_bucket():
    return collections.Counter(), collections.Counter(), [0, 0, 0]


@lru_cache(maxsize=64)
def future_hour(hour):
    try:
        return datetime.datetime.strptime(hour, hour_format) > now.astimezone().replace(tzinfo=None)
    except ValueError:
        return False

# Anchor both ends of the previously consumed prefix to detect truncation/rewrite.
def anchor(fd, offset):
    return hashlib.sha256(os.pread(fd, min(4096, offset), 0) +
        os.pread(fd, min(4096, offset), max(0, offset-4096))).hexdigest()

cache_hits = bytes_read = 0
seen = set()
show('Scanning:', prefix, '|', mode, '|', 'live+rotated' if rotated_ok else 'live', flush=True)
for path in discover():
    if not ROT_RE.search(path.name): continue
    domain = path.name.split('-access-log', 1)[0]
    try:
        source, st = open_log(path)
        with source:
            if not path.name.endswith('-access-log') and not rotated_ok and time.time()-st.st_mtime >= RECENT_SECONDS: continue
            identity = (st.st_dev, st.st_ino)
            if identity in seen: continue
            seen.add(identity)
            incremental = cache_enabled and path.suffix != '.gz'
            key = f'{st.st_dev}:{st.st_ino}:{domain}'
            saved = old_cache.get(key, {}) if cache_enabled else {}
            compressed = path.suffix == '.gz'
            fingerprint = [st.st_size, st.st_mtime_ns, st.st_ctime_ns]
            gzip_hit = compressed and saved.get('fingerprint') == fingerprint
            buckets = collections.defaultdict(new_bucket)
            lm = lo = offset = 0
            has_future_records = False
            if saved:
                try:
                    pos = saved['offset']
                    if gzip_hit or (incremental and 0 <= pos <= st.st_size and saved['anchor'] == anchor(source.fileno(), pos)):
                        buckets.update({hour: restore_bucket(bucket) for hour, bucket in saved['buckets'].items()
                                        if not hourly_cache or hour in live_hours})
                        lm, lo = saved['malformed'], saved['oversized']
                        offset = pos; cache_hits += 1
                except (KeyError, TypeError, ValueError):
                    buckets.clear(); lm = lo = offset = 0; gzip_hit = False
            source.seek(offset)
            reader = gzip.GzipFile(fileobj=source) if path.suffix == '.gz' else source
            try:
                while not gzip_hit:
                    line = reader.readline(MAX_LINE + 1)
                    if not line: break
                    bytes_read += len(line)
                    if len(line) > MAX_LINE:
                        consumed = len(line)
                        while not line.endswith(b'\n'):
                            line = reader.readline(MAX_LINE + 1)
                            if not line: break
                            consumed += len(line); bytes_read += len(line)
                        # Do not commit a partially written oversized record.
                        if incremental and not line.endswith(b'\n'): break
                        if incremental: offset += consumed
                        lo += 1; lm += 1; continue
                    # A live file may end in a partially written record; retry it later.
                    if incremental and not line.endswith(b'\n'): break
                    if incremental: offset += len(line)
                    m = pattern.match(line.decode('utf-8', errors='replace'))
                    if not m: lm += 1; continue
                    hour = m[2][:len(live_hours[0])] if hourly_cache else ''
                    if not in_period(m[2]):
                        # Leave this file uncached if an already-read record may
                        # enter the reporting window after it advances.
                        if hourly_cache and future_hour(hour): has_future_records = True
                        continue
                    bucket_counts, bucket_reasons, bucket_stats = buckets[hour]
                    try:
                        ip = ipaddress.ip_address(m[1])
                        if '%' in m[1]: raise ValueError('scoped IP')
                    except ValueError: bucket_stats[2] += 1; continue
                    bucket_stats[0] += 1
                    if mode == '--top-ip':
                        allips[ip] += 1; ipdomains[ip][domain] += 1; continue
                    if mode == '--top-sites': allsites[domain] += 1; continue
                    if mode == '--inspect':
                        if inspect == ip: print(repr(domain), m[2], repr(m[3]))
                        continue
                    if excluded(ip, allow): bucket_stats[1] += 1; continue
                    raw, matches = match_target(m[3])
                    if not matches: continue
                    if mode == '--top-urls': urls[(domain, raw)] += 1; continue
                    bucket_counts[ip] += 1
                    bucket_reasons.update((ip, w) for w in matches)
            finally:
                if reader is not source: reader.close()
            if compressed:
                end_st = os.fstat(source.fileno())
                if [end_st.st_size, end_st.st_mtime_ns, end_st.st_ctime_ns] != fingerprint:
                    raise OSError('gzip changed during scan')
            malformed += lm; oversized += lo
            for bucket_counts, bucket_reasons, (lr, ls, li) in buckets.values():
                requests += lr; skipped += ls; malformed += li
                counts.update(bucket_counts)
                if bucket_counts: domains[domain] += sum(bucket_counts.values())
                for (ip, word), n in bucket_reasons.items(): reasons[ip][(domain, word)] += n
            if cache_enabled and not has_future_records:
                new_cache[key] = {'offset': offset, 'anchor': anchor(source.fileno(), offset), 'fingerprint': fingerprint if compressed else None,
                    'malformed': lm, 'oversized': lo, 'buckets': {hour: save_bucket(bucket) for hour, bucket in buckets.items()}}
            files += 1
    except UnsafeLog as e:
        unsafe += 1; print(f'WARNING: unsafe log skipped: {str(path)!r}: {str(e)!r}', file=sys.stderr)
    except DisappearedLog as e:
        disappeared += 1; print(f'WARNING: log disappeared/replaced: {str(path)!r}: {str(e)!r}', file=sys.stderr)
    except (OSError, EOFError, zlib.error) as e:
        unreadable += 1; print(f'WARNING: cannot fully read {str(path)!r}: {str(e)!r}', file=sys.stderr)

if cache_enabled and files:
    tmp = None
    try:
        with tempfile.NamedTemporaryFile(mode='w', encoding='utf-8', dir=cache_path.parent, delete=False) as cf:
            tmp = pathlib.Path(cf.name); json.dump({'key':cache_key,'hour':live_hours[-1],'files':new_cache}, cf, separators=(',',':'))
        if tmp.stat().st_size <= CACHE_LIMIT: tmp.replace(cache_path)
        else: tmp.unlink(); print('Cache exceeds size limit; not saved', file=sys.stderr)
    except OSError as e:
        print('Cache write failed:', str(e), file=sys.stderr)
        if tmp: tmp.unlink(missing_ok=True)
if cache_enabled: show(f'Incremental cache: {cache_hits}/{files} files | Read: {bytes_read} bytes')
# Never make firewall changes after an incomplete scan.
scan_ok = bool(files) and not unreadable
for label, value in [('Unsafe entries skipped', unsafe), ('Disappeared files', disappeared),
                     ('Read errors', unreadable), ('Oversized records', oversized)]:
    print(f'{tr(label)}: {paint(value, ("31" if label == "Read errors" else "33") if value else "32")}')
show(f'{tr("Scan status")}: {tr("OK" if scan_ok else "INCOMPLETE")}', color="32" if scan_ok else "31")
scan_elapsed = time.monotonic() - started_at
print(f'{tr("Scan time (s)")}: {scan_elapsed:.3f}', flush=True)
if mode == '--ban' and not scan_ok: sys.exit('Scan incomplete; no bans applied')

if mode in ('--top-ip', '--top-sites', '--top-urls', '--inspect'):
    if mode == '--top-ip':
        headings = {'ru': ('Запросы', 'IP', 'Домены (запросы)'), 'uk': ('Запити', 'IP', 'Домени (запити)'), 'en': ('Requests', 'IP', 'Domains (requests)')}
        a, b, c = headings[lang]
        print(f'{a:>8}  {b:<39}  {c}')
        for ip, n in allips.most_common(30):
            detail = ', '.join(f'{d.encode("unicode_escape").decode("ascii")} ({v})' for d, v in ipdomains[ip].most_common())
            print(f'{n:8d}  {str(ip):<39}  {detail}')
    elif inspect is None:
        for item, n in {'--top-sites': allsites, '--top-urls': urls}[mode].most_common(30): print(n, repr(item))
    print('Files:', files, 'Requests:', requests); sys.exit(0 if files and not unreadable else 1)

phase_started = time.monotonic()
resolve_zone()
eligible = [(ip, n) for ip, n in counts.most_common() if n >= minimum]
for index, (ip, n) in enumerate(eligible, 1):
    reason = ', '.join(f'{d}:{w} ({c})' for (d, w), c in reasons[ip].most_common()).encode('unicode_escape').decode('ascii')
    if mode == '--ban':
        show(f'[{index}/{len(eligible)}] {tr("Checking IP")}: {ip} | {n}', flush=True)
        ip_started = time.monotonic()
        status = ban(ip, n, reason)
        show(f'[{index}/{len(eligible)}] {status} | {tr("IP processing time (s)")}: {time.monotonic()-ip_started:.3f}', color=STATUS_COLOR.get(status, '36'), flush=True)
    else:
        q = query(ip, zone) if zone else None
        status = 'ALREADY-BANNED' if ok(q) else ('DRY-RUN' if q is not None and q.returncode == 1 else 'UNKNOWN-FIREWALL')
        show(status, ip, n, reason, color=STATUS_COLOR.get(status, "36"))
    statuses[status] += 1

print(f'{tr("Ban phase time (s)" if mode == "--ban" else "Check phase time (s)")}: {time.monotonic()-phase_started:.3f}', flush=True)
print(f'{tr("Total time (s)")}: {time.monotonic()-started_at:.3f}', flush=True)
show("\n========== " + tr("SCAN SUMMARY") + " ==========")
for key, value in [('Log files scanned', files), ('Requests in period', requests), ('Excluded requests', skipped),
                   ('Malformed lines (all periods)', malformed), ('Matched requests', sum(counts.values())),
                   ('Matched IPs', len(counts)), ('Below threshold', sum(n < minimum for n in counts.values())),
                   ('Eligible IPs', sum(n >= minimum for n in counts.values())), ('New bans', statuses['BANNED']),
                   ('Already banned', statuses['ALREADY-BANNED']), ('Would ban (dry-run)', statuses['DRY-RUN']),
                   ('Firewall status unknown', statuses['UNKNOWN-FIREWALL']), ('Errors', statuses['ERROR'])]:
    color = {'New bans':'32', 'Already banned':'33', 'Would ban (dry-run)':'94',
             'Errors':'31' if value else '32', 'Firewall status unknown':'33' if value else '32'}.get(key)
    print(f'{tr(key):36} {paint(value, color) if color else value}')
show("\n========== " + tr("MATCHES BY DOMAIN") + " ==========")
for d, n in domains.most_common(): print(n, d.encode('unicode_escape').decode('ascii'))
if not files or statuses['ERROR'] or unreadable: sys.exit(1)
PY
