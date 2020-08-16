import sys
import json
data = json.load(open('messages.json'))
print(data[data.keys[0]])