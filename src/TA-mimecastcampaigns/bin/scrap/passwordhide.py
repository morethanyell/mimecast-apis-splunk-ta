class MyScript(Script):    
	# Define some global variables    
	MASK = "<nothing to see here>"
	APP = __file__.split(os.sep)[-3]    
	USERNAME = None
	CLEAR_PASSWORD = None

def stream_events(self, inputs, ew):    
	self.input_name, self.input_items = inputs.inputs.popitem()
    session_key = self._input_definition.metadata["session_key"]    
	username = self.input_items["username"]    
	password = self.input_items['password']    
	self.USERNAME = username    
	try:        
		# If the password is not masked, mask it.
        if password != self.MASK:
			self.encrypt_password(username, password, session_key)
			self.mask_password(session_key, username)
			self.CLEAR_PASSWORD = self.get_password(session_key, username)
	except Exception as e:
		ew.log("ERROR", "Error: %s" % str(e))
		ew.log("INFO", "USERNAME:%s CLEAR_PASSWORD:%s" % (self.USERNAME, self.CLEAR_PASSWORD))
		
def encrypt_password(self, username, password, session_key):
    args = {'token':session_key}    
	service = client.connect(**args)    
	try:        
		# If the credential already exists, delte it.        
		for storage_password in service.storage_passwords:            
			if storage_password.username == username:
				service.storage_passwords.delete(username = storage_password.username)
                break        
			# Create the credential.        
			service.storage_passwords.create(password, username)    
		except Exception as e:
			raise Exception, "An error occurred updating credentials. Please ensure your user account has admin_all_objects and/or list_storage_passwords capabilities. Details: %s" % str(e)

def mask_password(self, session_key, username):    
	try:        
		args = {'token':session_key}        
		service = client.connect(**args)        
		kind, input_name = self.input_name.split("://")        
		item = service.inputs.__getitem__((input_name, kind))        
		kwargs = { "username": username, "password": self.MASK }
        item.update(**kwargs).refresh()    
    except Exception as e:
        raise Exception("Error updating inputs.conf: %s" % str(e))
     
def get_password(self, session_key, username):
    args = {'token':session_key}    
    service = client.connect(**args)    
    # Retrieve the password from the storage/passwords endpoint     
    for storage_password in service.storage_passwords:        
        if storage_password.username == username:            
            return storage_password.content.clear_password