from scapy.all import *

protocol_to_frames = {}
protos = {}

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
	global protocol_to_frames
	global protos
	
	for i in range(len(frames)):
		frame=frames[i]
		for prot in get_all_prot(frame):
			if prot in protos:
				protocol_to_frames[prot].append(i)
				protos[prot]+=1
			else:
				protocol_to_frames[prot]=list()
				protocol_to_frames[prot].append(i)
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
	print(protocol_to_frames)

if __name__ == '__main__':
	main()