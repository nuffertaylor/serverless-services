import hashlib
import random
import time

class UserBase:

  ### Interface Methods ###

  def getUser(self, username):
    pass

  def updateUserAuthtoken(self, username, authtoken, expiry):
    pass

  #userData is an object containing whatever data you require to be stored.
  def addUser(self, userData):
    pass


  ### Implemented Methods ###

  def handleRegister(self, username, password, email, ip):
    if(self.getUser(username)): raise Exception("username %s is already taken" %username)
    salt = self.genSalt()
    hashedPassword = self.hashAndSalt(password, salt)
    authtoken = self.registerUser(username, hashedPassword, salt, email, ip)
    return {"username" : username, "authtoken" : authtoken}

  def handleLogin(self, username, password):
    userData = self.getUser(username)
    if(not userData): raise Exception("User '%s' does not exist." %username)
    if(self.hashAndSalt(password, userData["salt"]) != userData["hashedPassword"]):
      raise Exception("Invalid password.")
    expiry = self.get7DaysFromNow()
    authtoken = self.genSalt()
    res = self.updateUserAuthtoken(username, authtoken, expiry)
    if(res):
      return {"username" : res["username"], "authtoken" : res["authtoken"]}
    raise Exception("Something went wrong, please try again later.")

  def registerUser(self, username, hashedPassword, salt, email, additionalParams):
    expiry = self.get7DaysFromNow()
    authtoken = self.genSalt()
    userData = {
      "username" : username,
      "hashedPassword" : hashedPassword,
      "email" : email,
      "authtoken" : authtoken,
      "expiry" : expiry,
      "salt" : salt,
    }
    userData.update(additionalParams)
    if(self.addUser(userData)):
      return authtoken
    else:
      return False
    

  ### Utility Methods ###

  def genSalt(self):
    return ''.join(random.choice("0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ") for i in range(32))
  
  def hashAndSalt(self, password, salt):
    return hashlib.sha512(password.encode('utf-8') + salt.encode('utf-8')).hexdigest()
  
  def get24HoursFromNow(self):
    return str(int( time.time() ) + (1000*60*24))
  
  def get7DaysFromNow(self):
    return str( int( time.time() ) + (7*1000*60*24))