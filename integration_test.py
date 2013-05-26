# integration tests for SecretStore
import socket
import random
import unittest
import base64
import time

host='localhost'
port=40713
max_resp_size=1024000 # max size of socket.recv() buffer
expected_bin_key_size_bytes=32 # expected size of a key (decoded)
expected_b64_key_size_bytes=44 # expected size of a b64-encoded key

class TestSecretStore(unittest.TestCase):
	ClassIsSetup = False

	def setUp(self):
		self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		self.s.connect((host, port))
		#print("Connected!")
		
	def tearDown(self):
		self.s.close()
	
	def get_response(self, req):
		self.s.sendall(req)
		data = self.s.recv(max_resp_size)
		#print 'Sent', repr(req)
		#print 'Recv', repr(data), "\n"
		return data

	def assertValidBase64(self, req):
		return True #TODO

	def assertNoError(self, response):
		return self.assertFalse("error:" in response)
	
	def assertError(self, response, errormsg):
		return self.assertTrue("error:" in response and errormsg in response, errormsg)
	
	def getNewline(self):
		if random.randint(0,1):
			return "\r\n"
		else:
			return "\n"

	def test_create_secret_get_secret(self):
		for requested_secret_len in range(1, 2000):
			key_resp=self.get_response("%d%s" % (requested_secret_len, self.getNewline()))[:-2]
			key_resp_len=len(key_resp)
			self.assertNoError(key_resp)
			self.assertValidBase64(key_resp)
			self.assertEquals(key_resp_len, expected_b64_key_size_bytes)
		
			bin_key=base64.b64decode(key_resp)
			self.assertEquals(len(bin_key), expected_bin_key_size_bytes)
			
			secret_resp=self.get_response("%s%s" % (key_resp, self.getNewline()))[:-2]
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
		resp=self.get_response("0\r\n")[:-2]
		self.assertError(resp, "new secret size invalid")
	
	def test_key_not_exist(self):
		key_resp=self.get_response("LOLzDlSD8zW1SGkANeucHVjdsYhJibVPhJvV/ah2Bs4=\r\n")[:-2]
		self.assertError(key_resp, "key not found during lookup")
	
	def test_invalid_request(self):
		key_resp=self.get_response("LOLzDlSD!!!!!!}{{}:?...eucHVjdsYhJibVPhJvV/ah2Bs4=\r\n")[:-2]
		self.assertError(key_resp, "request contains invalid characters")
	
	def test_empty_request(self):
		for newline in ["\r\n","\n"]:
			key_resp=self.get_response(newline)[:-2]
			self.assertError(key_resp, "zero length request")
	
	# needs investigation
	def test_missing_newline(self):
		start_time=time.time()
		resp=self.get_response("123912391239")
		#print("missing newline (timeout?) resp: '%s'" % str(resp))
		end_time=time.time()
		#print("missing newline request took %s sec" % str(end_time-start_time))

	def test_multiple_newlines(self):
		#print(str(time.time()))
		resp=self.get_response("12391239123\nfoobar\nhellowooo\n")
		#print("multiple newlines test resp: '%s'" % str(resp))
		#print(str(time.time()))
		# TODO assert

	def test_fuzz_large_commands(self):
		for x in range(0,11):
			#send exponetually larger strings.
			resp=self.get_response("A"*(2^x)+"\n")
			#make sure we have some kind of response. 
			self.assertRegexpMatches(resp, "\n$","Incomplete response: '%s'" % str(resp))

	def test_invalid_chars(self):
		requested_secret_len=128
		key_resp=self.get_response("%d\n" % (requested_secret_len))[:-2]
		
		# prepend fuzzed char to the key request
		for char_i in range(0,128):
			resp=self.get_response("%s%s\n" % (chr(char_i), key_resp))
			#self.assertError(key_resp, "key not found during lookup: '%s'" % resp)
			self.assertRegexpMatches(resp, "\n$","incomplete response: '%s'" % str(resp))
		
		# append fuzzed char to the key request
		for char_i in range(0,128):
			resp=self.get_response("%s%s\n" % (key_resp, chr(char_i)))
			#self.assertError(resp, "key not found during lookup: '%s'" % resp)
			self.assertRegexpMatches(resp, "\n$","incomplete response: '%s'" % str(resp))
		
		# just the char by itself
		for char_i in range(0,128):
			resp=self.get_response("%s\n" % (chr(char_i)))
			self.assertRegexpMatches(resp, "\n$","incomplete response: '%s'" % str(resp))	
		
		
if __name__ == '__main__':
	unittest.main()
