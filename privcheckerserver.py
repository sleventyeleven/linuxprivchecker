#!/usr/bin/env python3
# server for hosting exploit search

try:
    from exploitdb import exploitdb
except:
    import os
    print("-"*80)
    print('Submodule not found. Setting up...')
    os.system('cd exploitdb; git submodule init; git submodule update')
    print("-"*80)
    print("Please run again for full functionality.")
    exit()
import socketserver

_PORT_ = 4521
_IP_ = '0.0.0.0'

class SearchHandler(socketserver.StreamRequestHandler):
    def handle(self):
        print('[+] Connection from '+ self.client_address[0])
        data = self.rfile.readline().decode().strip()
        while not data == '':
            print('[ ] Searching for: ' + data)
            output = [ ]
            results = self.server.search(data)
            for exploits in results:
                output.append(exploits[0]['description'] + ' id: ' + exploits[0]['id'])
            if len(output) > 0:
                print(''.join(output))
                self.wfile.write('\n'.join(output).encode() + b'\n')
            data = self.rfile.readline().decode().strip()
        print('[-] Closing connection from ' + self.client_address[0])
        


class ExploitServer(exploitdb.ExploitSearch, socketserver.ThreadingMixIn, socketserver.TCPServer):
    def __init__(self, connectionInfo, handler):
        exploitdb.ExploitSearch.__init__(self)
        socketserver.TCPServer.__init__(self, connectionInfo, handler)
        socketserver.ThreadingMixIn.__init__(self)
    

        


def main():
    exploit = ExploitServer((_IP_, _PORT_), SearchHandler)
    print('[ ] Starting server on port ' + str(_PORT_))
    try:
        exploit.serve_forever()
    except:
        print('[-] Caught exception. Shutting down.')
        exploit.shutdown()
        exploit.server_close()
    
if __name__ == "__main__":
    main()