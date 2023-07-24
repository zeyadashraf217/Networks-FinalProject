import socket
import time


class TCPClient:
    def __init__(self, ip='localhost', port=5005):
        self.ip = ip
        self.port = port
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.seq_num = 0

    def connect(self):
        self.sock.connect((self.ip, self.port))
        # Send SYN message
        syn_message = "SYN"
        self.sock.send(syn_message.encode())
        # Receive SYN-ACK message
        synack_message = self.sock.recv(1024).decode()
        if synack_message == "SYNACK":
            # Send ACK message
            ack_message = "ACK"
            self.sock.send(ack_message.encode())
            print("Connection established")
        else:
            print("Failed to establish connection")

    def send(self, message):
        message_with_checksum = message + str(self.seq_num)
        checksum = sum(ord(c) for c in message_with_checksum) % 256
        message_with_checksum += chr(checksum)
        try:
            self.sock.sendall(message_with_checksum.encode())
            response = self.sock.recv(4096).decode()
            received_checksum = ord(response[-1])
            if received_checksum == (sum(ord(c) for c in response[:-1]) % 256):
                if (response[:-1] == 'ACK'):
                    self.seq_num = 1 - self.seq_num
                    data = self.sock.recv(4096).decode()
                    if data:
                        print(data)
                else:
                    self.send(message)
            else:
                self.send(message)
        except socket.error:
            print("Connection not available")
            self.sock.close()

    def close(self):
        self.send('FIN')
        print('connection has been closed')
        self.sock.close()


if __name__ == '__main__':
    client = TCPClient()
    client.connect()
    # # Test Case 1: in case of timeout
    # client.send(
    #     'GET http://localhost/leo.txt HTTP/1.1\r\nHost: www.example.com\r\nkeep-alive: 5\r\nconnection: keep-alive\r\n\r\n')
    # time.sleep(10)
    # client.send(
    #     'POST http://localhost/leo.txt HTTP/1.1\r\nHost: www.example.com\r\nconnection: close\r\n\r\nleeooo')
    # Test Case 2 : in case of closing the connection by setting the flag FIN (Get Request)
    # client.send(
    #     'GET http://localhost/leo.txt HTTP/1.1\r\nHost: www.example.com\r\nkeep-alive: 5\r\nconnection: keep-alive\r\n\r\n')
    # client.close()
    # # Test Case 3 : in case of POST request
    # client.send(
    #     'POST http://localhost/leo.txt HTTP/1.1\r\nHost: www.example.com\r\nkeep-alive: 5\r\nconnection: keep-alive\r\n\r\nleooo')
    # client.close()
    # # Test Case 4 : in case of connection header = close
    # client.send(
    #     'GET http://localhost/leo.txt HTTP/1.1\r\nHost: www.example.com\r\nkeep-alive: 0\r\nconnection: close\r\n\r\n')
    # client.send(
    #     'GET http://localhost/leo.txt HTTP/1.1\r\nHost: www.example.com\r\nkeep-alive: 0\r\nconnection: close\r\n\r\n')
    # # Test Case 5 : File doesn't exist
    # client.send(
    #     'GET http://localhost/ssss.txt HTTP/1.1\r\nHost: www.example.com\r\nkeep-alive: 5\r\nconnection: keep-alive\r\n\r\n')
    # client.close()
    # # Test Case 6 : Sending multiple requests
    client.send(
        'GET http://localhost/leo.txt HTTP/1.1\r\nHost: www.example.com\r\nkeep-alive: 5\r\nconnection: keep-alive\r\n\r\n')
    client.send(
        'GET http://localhost/leo.txt HTTP/1.1\r\nHost: www.example.com\r\nkeep-alive: 5\r\nconnection: keep-alive\r\n\r\n')
    client.send(
        'GET http://localhost/leo.txt HTTP/1.1\r\nHost: www.example.com\r\nkeep-alive: 5\r\nconnection: keep-alive\r\n\r\n')
    client.close()
