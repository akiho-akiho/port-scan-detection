# f = open("corrected")
# line = f.readline()

for line in open("yeye~"):
	line = line.replace('normal.','1')
	line = line.replace('portsweep.','2')
	print line


