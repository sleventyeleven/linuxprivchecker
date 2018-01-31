#!/usr/bin/env python3
###############################################################################################################
## [Title]: privcheckerserver.py -- a Linux Privilege Escalation Check Script Server
## [Author]: Mike Merrill (linted) -- https://github.com/linted
##-------------------------------------------------------------------------------------------------------------
## [Details]:
## This script is intended to be executed remotely to enumerate search for common privilege escalation  
## exploits found in exploit-db's database
##-------------------------------------------------------------------------------------------------------------
## [Warning]:
## This script comes as-is with no promise of functionality or accuracy.
##-------------------------------------------------------------------------------------------------------------
## [Modification, Distribution, and Attribution]:
## Permission is herby granted, free of charge, to any person obtaining a copy of this software and the
## associated documentation files (the "Software"), to use, copy, modify, merge, publish, distribute, and/or
## sublicense copies of the Software, and to permit persons to whom the Software is furnished to do so, subject
## to the following conditions:
##
## The software must maintain original author attribution and may not be sold
## or incorporated into any commercial offering.
##
## THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR ## IMPLIED, INCLUDING BUT NOT
## LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO
## EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES, OR OTHER LIABILITY, WHETHER
## IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE
## USE OR OTHER DEALINGS IN THE SOFTWARE.
###############################################################################################################

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