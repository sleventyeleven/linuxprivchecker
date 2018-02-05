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
    import socketserver
    from os.path import isfile
    import argparse
    import multiprocessing
    from csv import DictReader
except Exception as e:
    print("Caught exception: {}\nAre you running with python3?".format(e))
    exit(1)


_PORT_ = 4521
_IP_ = '0.0.0.0'
_SEARCHSPLOIT_ = "/usr/share/exploitdb/files_exploits.csv"

class SearchHandler(socketserver.StreamRequestHandler):
    def handle(self):
        try:
            print('[+] Connection from '+ self.client_address[0])
            self.pool = multiprocessing.Pool(10)
            for output in self.pool.imap(SearchHandler.search, iter(self.rfile.readline, b'\n')):
                if output:
                    print(output)
                    self.wfile.write(output.encode() + b'\n')
                
            self.pool.close()
            print('[$] Closing connection from {}\n'.format(self.client_address[0]))
            self.pool.join()
        except Exception as e:
            self.pool.terminate()
            self.wfile.write('[-] Exception Caught: {}'.format(e).encode())
            print("[-] Exception Caught: {}".format(e))
            self.pool.join()

    @classmethod
    def search(cls, data):
        query = data.decode().strip().split(" ")
        query[-1] = query[-1][:3] #cut down on the last item which should be the version number
        output = []
        for rows in ExploitServer.exploitDatabase:
            if all([term in rows["description"] for term in query]):
                output.append('\t'.join((rows["description"], rows["file"])))
        if output:
            return "[ ] " + "\n".join([' '.join(query), *output])



class ExploitServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
   exploitDatabase = []
    

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
    parser.add_argument("-f", "--file", help="The exploit csv to use")
    args = parser.parse_args()
    if args.ip:
        _IP_ = args.ip
    if args.port:
        _PORT_ = args.port
    if args.file:
        _SEARCHSPLOIT_ = args.file

    if not isfile(_SEARCHSPLOIT_):
        print("[-] Cannot find csv databse: {}\nFor more details visit: https://github.com/offensive-security/exploit-database".format(_SEARCHSPLOIT_))
        exit(2)

       #parse the exploit database and collect all the results
    try:
        with open(_SEARCHSPLOIT_) as Fin:
            reader = DictReader(Fin)
            for lines in reader:
                #add the database to the exploit server for non global persistance... or maybe it is technically still global?
                ExploitServer.exploitDatabase.append(lines)
    except Exception as e:
        print("[-] Exception caught while attempting to parse database file. {}".format(e))
        exit(3)

    print("[ ] Starting up")
    main()