import socket
choose=True
while choose:
	print("\nMenu\n(1)Get Host by Name \n(2)Get Host by Address\n(3)Quit")
	choose=raw_input("Enter the choice ")
	if choose=="1":
		addr1 = socket.gethostbyname('google.com')
		print(addr1)
		
	elif choose=="2":
		addr3=socket.gethostbyaddr("216.58.199.142")
		print(addr3)
        elif choose=="3":
		exit()	
        else:
        	print("Invalid choice, please choose again")
        	print("\n")

