import threading
import socket
import signal
try:
 sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
 port = int(input('Type the port number: '))
 sock.connect(('127.0.0.1', port))
 ex_event = threading.Event()
 def trd_lis():
     while True:
          tdata = sock.recv(1024).decode('utf-8')
          print (tdata)
          if ex_event.is_set():
             break
 def trd_snd():
     while True:
          msg = input()
          sock.send(msg.encode('utf-8'))
          if ex_event.is_set():
             sock.close()
             break
 def signal_handler(signum, frame):
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
  pass
except ConnectionRefusedError:
  print("*Connection refused. Please run SERVER before running the CLIENT.*")
except Exception:
  print('Error')
  pass
