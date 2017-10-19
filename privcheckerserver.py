#!/usr/bin/env python3
# server for hosting exploit search

from exploitdb import exploitdb
import socketserver

_PORT_ = 4521
_IP_ = '0.0.0.0'

class SearchHandler(socketserver.StreamRequestHandler):
    def handle(self):
        output = []
        data = self.rfile.readline().decode().strip()
        while not 'done' in data:
            print(data)
            results = self.server.search(data)
            print(results)
            for exploits in results:
                output.append(exploits[0]['description'] + ' id: ' + exploits[0]['id'])
            data = self.rfile.readline().decode().strip()
        buff = '\n'.join(output).encode()
        self.wfile.write(buff)
        


class ExploitServer(exploitdb.ExploitSearch, socketserver.ThreadingMixIn, socketserver.TCPServer):
    def __init__(self, connectionInfo, handler):
        exploitdb.ExploitSearch.__init__(self)
        socketserver.TCPServer.__init__(self, connectionInfo, handler)
        socketserver.ThreadingMixIn.__init__(self)
    

        


def main():
    exploit = ExploitServer((_IP_, _PORT_), SearchHandler)
    print('[ ] Starting server on port ' + str(_PORT_))
    exploit.serve_forever()
    
if __name__ == "__main__":
    main()