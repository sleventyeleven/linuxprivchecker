#!/usr/bin/env python3
# server for hosting exploit search

try:
    import socketserver
    from shutil import which
    import argparse
    import re
    import subprocess
    import json
    import multiprocessing
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
            self.pool = multiprocessing.Pool(5)
            for output in p.imap_unordered(self.search, iter(str(self.rfile.readline), '\n')):
                if not output[0]:
                    #error'd out. print the results, but don't send them on?
                    print(output[1])
                    continue
                if json.loads(output[1]).get("results", False):
                    print('[+] Found results for: {}'.format(' '.join(term)))
                    self.wfile.write(output.encode())
                else:
                    print('[-] No results for: {}'.format(' '.join(term)))

            self.pool.close()
            self.pool.join()
            print('[$] Closing connection from {}\n'.format(self.client_address[0]))
        except Exception as e:
            self.pool.terminate()
            self.wfile.write('{{"SEARCH":"ERROR", "RESULTS":"{}"}}'.format(e).encode())
            print("[-] Exception Caught: {}".format(e))
            self.pool.join()

    def search(data):
        try:
            term = data.decode().strip().split(" ")
            term[-1] = term[-1][:3] #cut down on the last item which should be the version number
            for splitTerms in term:
                if not re.search("^[\w:\-\+\.~_]+$", splitTerms):
                    return [False, "[-] recieved search term with invalid characters: {}".format(data.decode().strip())] #bad term return so we don't search it
            else:
                proc = subprocess.Popen([_searchsploit, '-j', *term], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
                output = proc.stdout.read()
            return [True, output]
 
        except Exception as e:
            return [False, "[-] ".format(e)]


class ExploitServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
   pass
    

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
    #parse the args
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--ip", help="Ip to listen on")
    parser.add_argument("-p", "--port", help="Port to listen on")
    args = parser.parse_args()
    if args.ip:
        _IP_ = args.ip
    if args.port:
        _PORT_ = args.port

    #make sure we have searchsploit accessable
    _searchsploit = which("searchsploit")
    if not _searchsploit:
        print("Please install searchsploit.\nFor more details visit: https://github.com/offensive-security/exploit-database")
        exit(2)

    print("[ ] Starting up")
    main()