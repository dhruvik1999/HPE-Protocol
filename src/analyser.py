from scapy.all import *

"""
	All main datastructures to use further.
"""
protocol_to_frames = {}
protos = {}
frames = []
total_time = 0

"""
	This functions reads the pcap file of addr address. rdpcap is the function of Scapy python library.

	@param addr address of the file
	@return frames all the freames from pcap file
"""
def readFile(addr):
	global frames
	frames=rdpcap(addr)
	return frames
	
def get_all_prot(frame):
	protos = []
	protos.append(frame.name)
	while frame.payload:
		frame = frame.payload
		protos.append(frame.name)
	return protos

def get_all_prot_used_with_frq(f_frames):
	global protocol_to_frames
	global protos
	global frames

	protocol_to_frames = {}
	protos = {}
	frames = f_frames

	for i in range(len(f_frames)):
		frame=f_frames[i]
		for prot in get_all_prot(frame):
			if prot in protos:
				protos[prot]+=1
			else:
				protos[prot]=1
	return protos

def get_protocol_to_frames(frames):
	global protocol_to_frames

	for i in range(len(frames)):
		frame=frames[i]
		for prot in get_all_prot(frame):
			if prot in protocol_to_frames:
				protocol_to_frames[prot].append(i)
			else:
				protocol_to_frames[prot]=list()
				protocol_to_frames[prot].append(i)
	return protocol_to_frames

def get_all_src_addr(proto):
	src_cnt = {}
	for pack in protocol_to_frames[proto]:
		pack=frames[pack]
		frame=pack[Ether]
		src=frame.src
		if src in src_cnt:
			src_cnt[src]+=1
		else:
			src_cnt[src]=1
	return src_cnt

def get_time_pcap_file(frames):
	return frames[ len(frames)-1 ].time-frames[0].time

def disp_prot_details(frames):
	global protos
	total_time = get_time_pcap_file(frames)
	protos = get_all_prot_used_with_frq(frames)
	print("protocol --> frequancy --> average")
	for proto in protos:
		print(proto," --> ",protos[proto]," --> ", protos[proto]/total_time)

def main():
	global frames
	frames = readFile('../data/test.pcap')
	# frames[0].show()	
	disp_prot_details(frames)
	# print(protocol_to_frames)
	print(protos)
	# get_proto_and_src_addr(protos)

if __name__ == '__main__':
	main()