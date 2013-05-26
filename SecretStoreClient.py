
import socket
import base64

host='localhost'
port=40713

class SecretStoreClient:
	def __init__(self, host, port):
		self.host=host
		self.port=port
		self.max_resp_size=1024000
		self.connect(host, port)
	
	def connect(self, host, port):
		self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		self.s.connect((host, port))
	
	def get_response(self, req):
		self.s.sendall(req)
		data = self.s.recv(self.max_resp_size)
		print 'Sent', repr(req)
		print 'Recv', repr(data), "\n"
		self.check_error(data)
		if "\r\n" in data:
			return data[:-2]
		return data
		
	def new_secret(self, size):
		return self.get_response("%d\r\n" % size)
	
	def get_secret(self, key_b64):
		return self.get_response("%s\r\n" % key_b64)
	
	def check_error(self, resp):
		if "error" in resp:
			raise Exception(resp)
	
store=SecretStoreClient(host, port)
k=store.new_secret(128)
v=store.get_secret(k)
print("k: %s\nv: %s\n\n" % (k, v))