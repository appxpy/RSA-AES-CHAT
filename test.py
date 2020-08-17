import sys
import json
data = json.load(open('messages.json'))
print(data)
del data[list(data.keys())[0]]
print(data)