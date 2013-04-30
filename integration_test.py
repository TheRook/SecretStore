# integration tests for SecretStore
import socket
import random
import unittest
import base64

host='localhost'
port=40713
max_resp_size=1024000 # max size of socket.recv() buffer
expected_bin_key_size_bytes=32 # expected size of a key (decoded)
expected_b64_key_size_bytes=44 # expected size of a b64-encoded key

class TestSecretStore(unittest.TestCase):
	ClassIsSetup = False

	def setUp(self):
		# If it was not setup yet, do it
		if not self.ClassIsSetup:
			print "Initializing environment"
			# run the real setup
			self.setupClass()
			# remember that it was setup already
			self.__class__.ClassIsSetup = True
	
	def setupClass(self):
		# Do the real setup
		unittest.TestCase.setUp(self)
		# you want to have persistent things to test
		#self.__class__.myclass = MyClass()
		# (you can call this later with self.myclass)
		print("Connecting to %s:%s...\n" % (host, port))
		self.__class__.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		self.__class__.s.connect((host, port))
		print("Connected!")
	
	def get_response(self, req):
		self.__class__.s.sendall(req)
		data = self.__class__.s.recv(max_resp_size)
		print 'Sent', repr(req)
		print 'Recv', repr(data), "\n"
		return data

	def assertValidBase64(self, req):
		return True #TODO

	def assertNoError(self, response):
		return self.assertFalse("error:" in response)
	
	def assertError(self, response, errormsg):
		return self.assertTrue("error:" in response and errormsg in response)
	
	def test_create_secret_get_secret(self):
		for requested_secret_len in range(1, 100):
			key_resp=self.get_response("%d\r\n" % requested_secret_len)[:-2]
			key_resp_len=len(key_resp)
			self.assertNoError(key_resp)
			self.assertValidBase64(key_resp)
			self.assertEquals(key_resp_len, expected_b64_key_size_bytes)
		
			bin_key=base64.b64decode(key_resp)
			self.assertEquals(len(bin_key), expected_bin_key_size_bytes)
			
			secret_resp=self.get_response("%s\r\n" % key_resp)[:-2]
			self.assertNoError(secret_resp)
			self.assertValidBase64(secret_resp)
			
			bin_secret=base64.b64decode(secret_resp)
			self.assertEquals(len(bin_secret), requested_secret_len)
	
	#define INVALID_KEY_SIZE "error: invalid key size for lookup"
	#define INVALID_SECRET_SIZE "error: new secret size invalid"
	#define KEY_NOT_EXIST "error: key not found during lookup"
	#define INVALID_REQUEST "error: request contains invalid characters"
	#define EMPTY_REQUEST "error: zero length request"
	#define REQUEST_TOO_LARGE "error: the request is too large"
	def test_invalid_key_size(self):
		key_resp=self.get_response("0\r\n")[:-2]
		self.assertError(key_resp, "new secret size invalid")
	
	def test_invalid_secret_size(self):
		key_resp=self.get_response("0\r\n")[:-2]
		self.assertError(key_resp, "new secret size invalid")
	
	def test_key_not_exist(self):
		key_resp=self.get_response("LOLzDlSD8zW1SGkANeucHVjdsYhJibVPhJvV/ah2Bs4=\r\n")[:-2]
		self.assertError(key_resp, "key not found during lookup")
	
	def test_invalid_request(self):
		key_resp=self.get_response("LOLzDlSD!!!!!!}{{}:?...eucHVjdsYhJibVPhJvV/ah2Bs4=\r\n")[:-2]
		self.assertError(key_resp, "request contains invalid characters")
	
	def test_empty_request(self):
		key_resp=self.get_response("\r\n")[:-2]
		self.assertError(key_resp, "zero length request")
	
	def test_request_too_large(self):
		#TODO
		pass
	
if __name__ == '__main__':
	unittest.main()