import pcapkit



def readPcap(addr):
	try:
		print("File reading .... : " + addr)
		return  pcapkit.extract(fin=addr, store=False, nofile=True, tcp=True, strict=True)

	except:
		print("Error in reading : " + addr)
		exit(0)

def getFrames(extraction):
	frames = []
	for i in extraction.frame:
		frames.append(i)	
	return frames


def main():
	# extraction = readPcap('test.pcap')
	# frames = getFrames(extraction)
	# frame0 = frames[0]

	# flag = pcapkit.ICMP in frame0
	# tcp = frame0[pcapkit.IP] if flag else None

	# print("Flag : ",flag)
	# print("TCP : ",tcp)

	#frames[0]=frames[1]
	# print(frames[1])
	#print(len(frames))

	# print("Length : " , len(extraction.frame))
	plist = pcapkit.extract(fin='test.pcap', fout='out.plist', format='plist', store=False)
	print(plist)

if __name__ == '__main__':
	main()

