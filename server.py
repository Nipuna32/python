import threading
import signal
import socket
from random import randint
try:
 sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
 sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR,1)
 port = randint(2000, 5000)
 sock.bind(('127.0.0.1', port))
 print ("***Use this port number '{}' to connect.***".format(port))
 sock.listen()
 conn, addr = sock.accept()
 print('Client connected to the server.')
 fmsg = "Welcome. You're connected."
 conn.send(fmsg.encode('utf-8'))
 ex_event = threading.Event()
 def trd_lis():
     while True:
          tdata = conn.recv(1024).decode('utf-8')
          print (tdata)
          if ex_event.is_set():
             break
 def trd_snd():
     while True:
          msg = input()
          conn.send(msg.encode('utf-8'))
          if ex_event.is_set():
             conn.close()
             break
 def signal_handler(signum, frame):
     sock.close()
     print("*Follow the instructions to exit program*")
     print("1. Press 'Ctrl+C' on both client and server-side")
     print("2. Press 'Enter' on both client and server-side")
     print("3. Press 'Ctrl+Z' to exit")
     ex_event.set()
 signal.signal(signal.SIGINT, signal_handler)
 xl = threading.Thread(target=trd_lis)
 xl.start()
 xt = threading.Thread(target=trd_snd)
 xt.start()
except KeyboardInterrupt:
  pass
except OSError:
  print("*Address already in use. You didn't correctly exit. Press 'Ctrl+C' to exit*")
  pass
except Exception:
  print('Error')
  pass
