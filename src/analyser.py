from scapy.all import *

def readFile(addr):
	return rdpcap(addr)

def get_all_prot(frame):
	protos = []
	protos.append(frame.name)
	while frame.payload:
		frame = frame.payload
		protos.append(frame.name)
	return protos


def get_all_prot_used_with_frq(frames):
	protos={}
	for frame in frames:
		for prot in get_all_prot(frame):
			if prot in protos:
				protos[prot]+=1
			else:
				protos[prot]=1
	return protos


def main():
	frames = readFile('test.pcap')
	protos = get_all_prot_used_with_frq(frames)
	for proto in protos:
		print(proto," --> ",protos[proto])


if __name__ == '__main__':
	main()