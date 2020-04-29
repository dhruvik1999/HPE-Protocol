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

def get_time_pcap_file(frames):
	return frames[ len(frames)-1 ].time-frames[0].time

def disp_prot_details(frames):
	total_time = get_time_pcap_file(frames)
	protos = get_all_prot_used_with_frq(frames)
	print("protocol --> frequancy --> average")
	for proto in protos:
		print(proto," --> ",protos[proto]," --> ", protos[proto]/total_time)

def main():
	frames = readFile('../data/test.pcap')	
	disp_prot_details(frames)
	for frame in frames:
		frame.show()
		pass

if __name__ == '__main__':
	main()