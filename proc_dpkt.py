from scapy.all import *

def readFile(addr):
	return rdpcap(addr)

def printDetails(frame):
	if frame.haslayer(Ether):
		print("Ether Layer ")
		print("		Destination : " , frame.dst)
		print("		Source 		: ", frame.src)
		print("		Type 		: " , frame.type)

	if frame.haslayer(IPv6):
		print('IPv6 Layer')
		print("		Version 	: ",frame[IPv6].version)
		print("		tc 			: ",frame[IPv6].tc)
		print("		fl 			: ",frame[IPv6].fl)
		print("		plen 		: ",frame[IPv6].plen)
		print("		nh 			: ",frame[IPv6].nh)
		print("		hlim 		: ",frame[IPv6].hlim)
		print("		src 		: ",frame[IPv6].src)
		print("		dst 		: ",frame[IPv6].dst)
	else:
		print('IPv4 Layer')
		print("		version : ",frame[IP].version)
		print("		ihl : ",frame[IP].ihl)
		print("		tos : ",frame[IP].tos)
		print("		len : ",frame[IP].len)
		print("		id : ",frame[IP].id)
		print("		flags : ",frame[IP].flags)
		print("		frag : ",frame[IP].frag)
		print("		ttl : ",frame[IP].ttl)
		print("		proto : ",frame[IP].proto)
		print("		chksum : ",frame[IP].chksum)
		print("		src : ",frame[IP].src)
		print("		dst : ",frame[IP].dst)
		print("		options : ",frame[IP].options)



	if frame.haslayer(TCP):
		print('TCP Layer')
		print("		sport : ",frame[TCP].sport)
		print("		dport : ",frame[TCP].dport)
		print("		seq : ",frame[TCP].seq)
		print("		ack : ",frame[TCP].ack)
		print("		dataofs : ",frame[TCP].dataofs)
		print("		reserved : ",frame[TCP].reserved)
		print("		flags : ",frame[TCP].flags)
		print("		window : ",frame[TCP].window)
		print("		chksum : ",frame[TCP].chksum)
		print("		urgptr : ",frame[TCP].urgptr)
		print("		options : ",frame[TCP].options)
	elif frame.haslayer(UDP):
		print('UDP')
#  ihl=5L tos=0x0 len=67 id=1 flags= frag=0L ttl=64 proto=TCP chksum=0x783c
#  src=192.168.5.21 dst=66.35.250.151 options=''



def main():
	pcap = readFile('test.pcap')
	# frame = pcap[100]
	#frame.show()
	for frame in pcap:
		if frame.haslayer(TCP):
			printDetails(frame)
			break


if __name__ == '__main__':
	main()