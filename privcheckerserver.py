#!/usr/bin/env python3
# server for hosting exploit search

try:
    import socketserver
    from shutil import which
    import argparse
    import re
    import subprocess
except Exception as e:
    print("Caught exception: {}\nAre you running with python3?".format(e))
    exit(1)


_PORT_ = 4521
_IP_ = '0.0.0.0'
_searchsploit = ""

class SearchHandler(socketserver.StreamRequestHandler):
    def handle(self):
        try:
            print('[+] Connection from '+ self.client_address[0])
            output = []
            for data in iter(self.rfile.readline, ''):
                term = data.decode().strip()
                if re.search("^[\w\s:\-\+\._]+$", term):
                    print("[-] recieved search term with invalid characters: {}".format(term))
                    continue

                print('[ ] Searching for: ' + term)
                splitTerms = term.split(" ")
                splitTerms[-1] = splitTerms[-1][:3] #cut down on the last item which should be the version number
                proc = subprocess.Popen([_searchsploit, *splitTerms], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
                self.wfile.write('{}\n'.format(proc.stdout.read()))
            print('[$] Closing connection from {}\n'.format(self.client_address[0]))
        except Exception as e:
            print("[-] Caught exception {}. Closing this connection.".format(e))
            self.wfile.write("[-] Server caught {}. Closing Connection".format(e))
        


class ExploitServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
   pass
    

def main():
    #make sure we have searchsploit accessable
    _searchsploit = which("searchsploit")
    if not _searchsploit:
        print("Please install searchsploit.\nFor more details visit: https://github.com/offensive-security/exploit-database")
        exit(2)

    exploit = ExploitServer((_IP_, _PORT_), SearchHandler)
    print('[ ] Starting server on port ' + str(_PORT_))
    try:
        exploit.serve_forever()
    except:
        print('[-] Caught exception. Shutting down.')
        exploit.shutdown()
        exploit.server_close()
    
if __name__ == "__main__":
    #parse the args
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--ip", help="Ip to listen on")
    parser.add_argument("-p", "--port", help="Port to listen on")
    args = parser.parse_args()
    if args.ip:
        _IP_ = args.ip
    if args.port:
        _PORT_ = args.port

    print("[ ] Starting up")
    main()