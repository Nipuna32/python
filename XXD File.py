import sys
try:
 file1=sys.argv[1]
 cont=open(file1,'rb')
 c = 0
 c2= 1
 list1=[]
 contopn = cont.read(16)
 while contopn:
    for i in contopn:
       if (c2%2!=0):
         list1.append(f" {i:02x}")
         c2=c2+1
       else:
         list1.append(f"{i:02x}")
         c2=c2+1
    line2 = "".join(list1)
    line3 = "".join([chr(i)  for i in contopn ]).replace('\n','.')
    print(f"{c * 16:08x}:{line2.ljust(40)}  {line3.ljust(16)}")
    c=c+1
    list1=[]
    contopn = cont.read(16)
except FileNotFoundError:
     print("There is no such a file.")
     pass
except Exception:
     pass
