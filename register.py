import json
import re
import datetime
from Cryptodome.Hash import SHA256

# 0 - No additional permissions
# 1 - Moderator - /whois command and /ban & /kick
# 2 - Admin - /serverstatus, /connectedcli, /stopserver & advanced /whois
#
DEFAULT_ACCESS_LEVEL = 0
f = open('users.json', 'r+')
obj = json.load(f, encoding='utf-8')
f.close()
print('New User Registration.\nLogin: 4 min, 25 max. Upper and lower case letters, numbers. Spaces and byte codes are prohibited. \nPassword : Minimum eight and maximum 10 characters, at least one uppercase letter, one lowercase letter, one number and one special character')
userlist = obj.keys()
login = str(input('Login > '))
pattern = re.compile(r'^(?=.{4,20}$)(?:[a-zA-Z\d]+(?:(?:\.|-|_)[a-zA-Z\d])*)+$')
if re.match(pattern, login) != None:
	if login in userlist:
		print('User with such nickname already registered!')
	else:
		password = str(input('Password > '))
		passwordconf = str(input('Confirm password > '))
		if password == passwordconf:
			pattern = re.compile(r'^(?=.*?[A-Z])(?=.*?[a-z])(?=.*?[0-9])(?=.*?[^\w\s]).{8,257}$')
			if re.match(pattern, password) != None:
				print('Default access level : {}. You can change it manually for this account in file users.json'.format(DEFAULT_ACCESS_LEVEL))
				register_time = str(datetime.datetime.now())
				obj[login] = [str((SHA256.new(password.encode('utf-8'))).hexdigest()), register_time, 'No data', 0, 0, 0]
				jsonobj = json.dumps(obj, indent=4, sort_keys=True)
				f = open('users.json', 'w', encoding='utf-8')
				f.write(jsonobj)
				f.close()
				print('Success!')
			else:
				print('Invalid password!')
		else:
			print('Password confirmation invalid!')
else:
	print('Invalid username!')

