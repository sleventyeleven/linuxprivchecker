#!/usr/bin/env python3
# server for hosting exploit search

from exploitdb import exploitdb
import socketserver


class ExploitServer(exploitdb.ExploitSearch, socketserver.StreamReqstHandler):
    def __init__(self, ip=None, port=None):
        super(exploitdb.ExploitSearch).__init__()
        pass


def main():
    exploit = ExploitServer()
    
if __name__ == "__main__":
    main()