x=int(input("Enter a value:" ))
total=0 
while x != 0:
    try:
        total=total+x
        print(total)
        x=int(input("Enter a value:" ))
        
    except KeyboardInterrupt:
        raise
    except:
        print("Incorrect value..")
        total=total-x
print(total)