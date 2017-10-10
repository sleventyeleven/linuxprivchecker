#!/usr/bin/env python3
# server for hosting exploit search

from exploitdb import exploitdb
import socketserver

_PORT_ = 4521
_IP_ = '0.0.0.0'

class SearchHandler(socketserver.StreamRequestHandler):
    def handle():
        self.data = self.rfile.readline().strip()
        results = self.server.search(data)
        output = '\n'.join([''.join(k,v) for k,v in results])
        self.wfile.write(output)
        #self.server <- use this is access the server


class ExploitServer(exploitdb.ExploitSearch, socketserver.ThreadingMixIn, socketserver.TCPServer):
    def __init__(self, connectionInfo, handler):
        super().__init__()
        super(exploitdb.ExploitSearch).__init__(connectionInfo, handler)
        


def main():
    exploit = ExploitServer((_IP_, _PORT_), SearchHandler)
    
if __name__ == "__main__":
    main()