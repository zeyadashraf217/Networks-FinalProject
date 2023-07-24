import socket
import datetime
import os.path
import threading


class TCPServer:
    def __init__(self, ip='localhost', port=5005):
        self.ip = ip
        self.port = port
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.bind((self.ip, self.port))
        self.seq_num = 0

    def handle_client(self, conn, addr):
        while True:
            try:
                data = conn.recv(4096)
                if data:
                    # break
                    message_with_checksum = data.decode()
                    received_checksum = ord(message_with_checksum[-1])
                    if received_checksum == sum(ord(c) for c in message_with_checksum[:-1]) % 256 and received_checksum != 0:
                        message = message_with_checksum[:-2]
                        ack_message = 'ACK'
                        checksum = sum(ord(c) for c in ack_message) % 256
                        ack_message += chr(checksum)
                        conn.sendall(ack_message.encode())
                        print("\nRequest:")
                        print(message)
                        if message.startswith("GET"):
                            http = HTTPRequest()
                            http.parse_request(message)
                            respond = http.GetHandler()
                            conn.sendall(respond.encode())
                            if http.headers['keep-alive']:
                                conn.settimeout(
                                    int(http.headers['keep-alive']))
                            if http.headers['connection'] == 'close':
                                print('Connection has been closed.')
                                conn.close()
                                break
                        if message.startswith("POST"):
                            http = HTTPRequest()
                            http.parse_request(message)
                            respond = http.POSTHandler()
                            conn.sendall(respond.encode())
                            if http.headers['keep-alive']:
                                conn.settimeout(
                                    int(http.headers['keep-alive']))
                            if http.headers['connection'] == 'close':
                                print('Connection has been closed.')
                                conn.close()
                                break
                        ack_message = str(self.seq_num)
                        self.seq_num = 1 - self.seq_num
                        if (message == 'FIN'):
                            print('Connection has been closed.')
                            conn.close()
                            break
            except socket.timeout:
                print('Connection has been closed.')
                conn.close()
                break

    def start(self):
        self.sock.listen()
        conn, addr = self.sock.accept()
        syn_message = conn.recv(4096).decode()
        if syn_message == "SYN":
            # Send SYN-ACK message
            synack_message = "SYNACK"
            conn.send(synack_message.encode())
            # Receive ACK message
            ack_message = conn.recv(4096).decode()
            if ack_message == "ACK":
                print("Connection established")
                thread = threading.Thread(
                    target=self.handle_client, args=(conn, addr))
                thread.start()
            else:
                print("Failed to establish connection")
                conn.close()
        else:
            print("Failed to establish connection")
            conn.close()


class HTTPRequest:
    def __init__(self, headers=None):
        self.method = None
        self.uri = None
        self.version = None
        self.headers = headers if headers is not None else {}
        self.body = ''
        self.time = 0

    def parse_request(self, request_string):
        lines = request_string.split('\r\n')
        request_line = lines[0].split()
        self.method = request_line[0]
        self.uri = request_line[1]
        self.version = request_line[2]

        for line in lines[1:-1]:
            if line:
                header_name, header_value = line.split(': ')
                self.headers[header_name] = header_value
        self.body = lines[-1]
        if 'Content-Length' in self.headers:
            content_length = int(self.headers['Content-Length'])
            self.body = ''.join(lines[-content_length:])

    def GetHandler(self):
        splits = self.uri.split('/')
        path = splits[3]
        time = datetime.datetime.utcnow().strftime('%a, %d %b %Y %H:%M:%S GMT')
        if os.path.isfile(path):
            f = open(path, "r")
            data = f.read()
            response = 200
            m_time = os.path.getmtime(path)
            date = datetime.datetime.fromtimestamp(
                m_time).strftime('%a, %d %b %Y %H:%M:%S GMT')
            respond = self.version + ' ' + str(response) + ' ' + 'OK\n' + 'data: ' + \
                time + '\nmodified_time: ' + \
                str(date)+'\ncontent length: '+str(len(data))
            if self.headers['keep-alive']:
                data += "\nKeep-alive: "+str(self.headers['keep-alive'])
            if self.headers['connection']:
                data += "\nconnection: "+str(self.headers['connection'])

            data += '\n' + data
            return respond
        else:
            response = 404
            data = None
            respond = self.version + ' ' + str(response) + ' ' + 'NOT FOUND\n'
            return respond

    def POSTHandler(self):
        splits = self.uri.split('/')
        path = splits[3]
        time = datetime.datetime.utcnow().strftime('%a, %d %b %Y %H:%M:%S GMT')
        if os.path.isfile(path):
            f = open(path, "a")
            f.write("\n")
            f.write(self.body)
            response = 200
            m_time = os.path.getmtime(path)
            date = datetime.datetime.fromtimestamp(
                m_time).strftime('%a, %d %b %Y %H:%M:%S GMT')
            respond = self.version + ' ' + str(response) + ' ' + 'OK\n' + 'data: ' + \
                time + '\nmodified_time: ' + \
                str(date)
            if self.headers['keep-alive']:
                data += "\nKeep-alive: "+str(self.headers['keep-alive'])
            if self.headers['connection']:
                data += "\nconnection: "+str(self.headers['connection'])

            return respond
        else:
            response = 404
            data = None
            respond = self.version + ' ' + str(response) + ' ' + 'NOT FOUND\n'
            return respond


if __name__ == '__main__':
    server = TCPServer()
    server.start()
