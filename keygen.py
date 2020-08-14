from threading import Timer
from time import sleep

def hello():
    print("Hello user!")

def bye():
    sleep(5)
    print("Bye...bye...")

while 1:
    timer = Timer(3, hello)
    timer.start()
    bye()