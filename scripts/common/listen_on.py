#!/usr/bin/env python3
# listen_on.py -- minimal TCP listener for the PwnEscape lab.
#
# Binds 0.0.0.0:7778, accepts connections, and parks each accepted socket in a
# thread.  The chain only needs the host to have a live listening socket and a
# populated SYN/accept path; the workqueue target itself is rt6_probe_deferred.
#
# Usage: sudo python3 listen_on.py [port]
import os
import socket
import sys
import threading
import time

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 7778
HOST = "0.0.0.0"


def park(c, a):
    try:
        c.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        while True:
            time.sleep(3600)
    except Exception:
        pass
    finally:
        try:
            c.close()
        except Exception:
            pass


def main():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((HOST, PORT))
    s.listen(4096)
    print("listen_on %s:%d pid=%d" % (HOST, PORT, os.getpid()), flush=True)
    while True:
        try:
            c, a = s.accept()
        except KeyboardInterrupt:
            return
        except Exception:
            continue
        threading.Thread(target=park, args=(c, a), daemon=True).start()



if __name__ == "__main__":
    main()
