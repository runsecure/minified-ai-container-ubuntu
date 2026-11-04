"""Runtime self-test for the chiseled Python images.

Feed it on stdin (the images have no shell and nothing to copy it in with):
    docker run -i --rm IMAGE python3 - [guarded] < tests/python-selftest.py

Exercises the parts of the stdlib that touch the OS in ways a seccomp filter
or a missing slice would break: TLS/CA bundle, OpenSSL hashes, sqlite, ctypes,
threads, subprocess, every multiprocessing start method, asyncio sockets,
DNS/NSS, compression, zoneinfo, UTF-8.

With "guarded", it also asserts that container-guard's filter is installed and
blocks what it should (no_new_privs, ptrace, user namespaces, personality).
"""
import sys

GUARDED = "guarded" in sys.argv[1:]
passed = failed = 0


def check(name):
    def wrap(fn):
        global passed, failed
        try:
            detail = fn()
            passed += 1
            print(f"ok   {name}" + (f": {detail}" if detail else ""))
        except Exception as e:  # noqa: BLE001 - report every failure, keep going
            failed += 1
            print(f"FAIL {name}: {type(e).__name__}: {e}")
        return fn
    return wrap


def _square(x):  # module level so spawn/forkserver can pickle it
    return x * x


@check("interpreter")
def _():
    import platform
    return f"{platform.python_version()} {platform.machine()}, utf8 fs={sys.getfilesystemencoding()}"


@check("stdlib precompiled (.pyc next to source)")
def _():
    import asyncio, importlib.util, os
    pyc = importlib.util.cache_from_source(asyncio.__file__)
    assert os.path.exists(pyc), pyc


@check("TLS context loads the CA bundle")
def _():
    import ssl
    ctx = ssl.create_default_context()
    n = ctx.cert_store_stats()["x509_ca"]
    assert n > 50, f"only {n} CA certs"
    return f"{n} CAs, {ssl.OPENSSL_VERSION}"


@check("hashlib (OpenSSL + builtin)")
def _():
    import hashlib
    assert hashlib.sha256(b"abc").hexdigest().startswith("ba7816bf")
    hashlib.blake2b(b"abc").hexdigest()
    hashlib.new("sha3_256", b"abc").hexdigest()


@check("sqlite3")
def _():
    import sqlite3
    db = sqlite3.connect(":memory:")
    db.execute("create table t(x)")
    db.executemany("insert into t values (?)", [(i,) for i in range(100)])
    assert db.execute("select sum(x) from t").fetchone()[0] == 4950
    return sqlite3.sqlite_version


@check("ctypes calls into libc")
def _():
    import ctypes, os
    assert ctypes.CDLL("libc.so.6").getpid() == os.getpid()


@check("zoneinfo")
def _():
    from datetime import datetime, timezone
    from zoneinfo import ZoneInfo
    t = datetime(2026, 7, 1, 12, tzinfo=timezone.utc).astimezone(ZoneInfo("America/New_York"))
    assert t.hour == 8, t


@check("compression (zlib, bz2, lzma)")
def _():
    import bz2, lzma, zlib
    data = b"minified " * 1000
    for m in (zlib, bz2, lzma):
        assert m.decompress(m.compress(data)) == data, m.__name__


@check("threads + ThreadPoolExecutor")
def _():
    from concurrent.futures import ThreadPoolExecutor
    with ThreadPoolExecutor(16) as ex:
        assert sum(ex.map(_square, range(100))) == 328350


@check("subprocess (re-exec the interpreter)")
def _():
    import subprocess
    out = subprocess.run([sys.executable, "-c", "print(6*7)"], capture_output=True, text=True, check=True)
    assert out.stdout.strip() == "42", out


# This script arrives on stdin, so spawn/forkserver children can't re-run __main__
# (its __file__ is the literal "<stdin>") or import functions defined in it. Hide
# __file__ while the pool starts and give the workers a stdlib function. The timeout
# turns a broken pool (which restarts dying workers forever) into a failure, not a hang.
for _method in ("fork", "spawn", "forkserver"):
    @check(f"multiprocessing Pool ({_method})")
    def _(method=_method):
        import math
        import multiprocessing as mp
        main = sys.modules["__main__"]
        saved = main.__dict__.pop("__file__", None)
        try:
            with mp.get_context(method).Pool(2) as pool:
                got = pool.map_async(math.factorial, range(10)).get(timeout=60)
        finally:
            if saved is not None:
                main.__file__ = saved
        assert got == [math.factorial(x) for x in range(10)], got


@check("asyncio TCP echo on loopback")
def _():
    import asyncio

    async def main():
        async def echo(r, w):
            w.write(await r.read(100))
            await w.drain()
            w.close()
        srv = await asyncio.start_server(echo, "127.0.0.1", 0)
        port = srv.sockets[0].getsockname()[1]
        r, w = await asyncio.open_connection("127.0.0.1", port)
        w.write(b"ping")
        await w.drain()
        data = await r.read(100)
        w.close()
        srv.close()
        return data

    assert asyncio.run(main()) == b"ping"


@check("name resolution (NSS: localhost, nonroot user)")
def _():
    import pwd, socket
    socket.getaddrinfo("localhost", 80)
    assert pwd.getpwuid(65532).pw_name == "nonroot"


@check("tempfile in /tmp")
def _():
    import tempfile
    with tempfile.NamedTemporaryFile() as f:
        f.write("héllo ✓".encode())
        f.flush()


@check("misc stdlib (json, decimal, xml, uuid, csv)")
def _():
    import csv, decimal, io, json, uuid
    import xml.etree.ElementTree as ET
    assert json.loads(json.dumps({"a": [1, 2]})) == {"a": [1, 2]}
    assert decimal.Decimal("0.1") + decimal.Decimal("0.2") == decimal.Decimal("0.3")
    assert ET.fromstring("<a><b>x</b></a>").find("b").text == "x"
    uuid.uuid4()
    list(csv.reader(io.StringIO("a,b\n1,2\n")))


if GUARDED:
    import ctypes, errno, os

    libc = ctypes.CDLL(None, use_errno=True)

    def status(key):
        with open("/proc/self/status") as f:
            for line in f:
                if line.startswith(key + ":"):
                    return line.split()[1]

    @check("guard: no_new_privs set, seccomp filter installed")
    def _():
        assert status("NoNewPrivs") == "1"
        assert status("Seccomp") == "2"
        return f"{status('Seccomp_filters')} filter(s)"

    @check("guard: ptrace -> EPERM")
    def _():
        assert libc.ptrace(0, 0, None, None) == -1  # PTRACE_TRACEME
        assert ctypes.get_errno() == errno.EPERM, os.strerror(ctypes.get_errno())

    @check("guard: unshare(CLONE_NEWUSER) -> EPERM")
    def _():
        try:
            os.unshare(os.CLONE_NEWUSER)
        except PermissionError:
            return
        raise AssertionError("unshare succeeded")

    @check("guard: personality(ADDR_NO_RANDOMIZE) -> EPERM")
    def _():
        assert libc.personality(0x0040000) == -1
        assert ctypes.get_errno() == errno.EPERM, os.strerror(ctypes.get_errno())

    @check("guard: filter inherited by child processes")
    def _():
        import subprocess
        out = subprocess.run(
            [sys.executable, "-c",
             "print([l.split()[1] for l in open('/proc/self/status') if l.startswith('Seccomp:')][0])"],
            capture_output=True, text=True, check=True)
        assert out.stdout.strip() == "2", out

print(f"python selftest ({'guarded' if GUARDED else 'plain'}): {passed} passed, {failed} failed")
sys.exit(1 if failed else 0)
