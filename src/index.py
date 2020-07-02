from tkinter import *
from tkinter import ttk
from tkinter import filedialog
import analyzer as anl
import matplotlib.pyplot as plt

class Window(Frame):
	def __init__(self, master=None):
		Frame.__init__(self, master)
		self.master = master
		self.init_window()
		self.filename=None
		self.frames=None
		self.protos=None
		self.total_time=None
		self.src_cnt=None
		self.protocol_to_frames=None
		self.tree = None
		self.scrollbar = None
		self.opt = None
		self.flt_val=0
		self.avg_flt_val=0

	"""
		This function will print the logs
		
		@param head,title,text
		@return null
	"""
	def printLog(self,head,title,text):
		print("[ ",head," ] ", title, " : ", text)

	"""
		Default function for Tkinter Ui python library

		@param null
		@return null
	"""
	def init_window(self):
		self.printLog("UI/UX", "window", "tkinter initiated")
		self.master.title("HPE - Protocol analyzer")
		self.pack(fill=BOTH, expand=1)

		lbl = Label(self,text="HPE Protocol analyzer",font=("Courier", 25))
		lbl.place(x=50,y=325)

		quitButton = Button(self, text="Protocol Analysis", command=self.make_protocol_table)
		quitButton.place(x=0, y=0)
		quitButton = Button(self, text="Intrusion Analysis",command=self.make_distrution_table)
		quitButton.place(x=150, y=0)

	"""
		This function will make the table for protocol analyzer. It has 3 coloumns, 1st for name of protocol
		and 2nd for Frequency of the protocol, and 3rd for average packet per second.

		@param null
		@return null
	"""
	def make_protocol_table(self):
		currdir = os.getcwd()
		self.printLog("Ui/UX","wondow","selecting file from system")
		self.filename =  filedialog.asksaveasfilename(parent=self,initialdir =currdir,title = "Select pcap file",filetypes = (("Pcap files","*.pcap"),("all files","*.*")))
		if self.filename!=():
			self.printLog("FileSystem","pcap file",self.filename)
		else:
			self.printLog("FileSystem","Error","File not entered...")
			self.printLog("System","Exit","")
			exit(0)

		self.printLog("FileSystem","Read","data reading from file")
		self.frames = anl.readFile(self.filename)
		self.printLog("System","Process","counting total time interval")
		self.total_time = anl.get_time_pcap_file(self.frames)
		self.printLog("System","Process","counting frquancy of each protocol")
		self.protos = anl.get_all_prot_used_with_frq(self.frames)
		treedata = []

		try:
			self.graphButton.destroy()
		except:
			pass

		self.graphButton = Button(self, text="Generate graph",command=self.make_protocol_table_graph )
		self.graphButton.place(x=700, y=0)

		self.printLog("System","Write","data is appending to the table")
		for proto in self.protos:
			treedata.append( ( proto , self.protos[proto] ,self.protos[proto]/self.total_time) )

		column_names = ("Protocols", "Frequency","Average Frequency")

		try:
			if self.tree != None:
				self.tree.destroy()
			if self.opt != None:
				self.opt.destroy()
			if self.scrollbar != None:
				self.scrollbar.destroy()
		except:
			pass

		self.scrollbar = ttk.Scrollbar(self)
		self.tree = ttk.Treeview(self, columns = column_names, yscrollcommand = self.scrollbar.set)
		self.scrollbar.pack(side = 'right', fill= Y)
		self.tree['show'] = 'headings'

		self.printLog("UI/UX","window","Table is being printing..")

		for col in column_names: 
			self.tree.heading(col, text = col)
		for x in treedata:
			self.tree.insert('', 'end', values=x)
		self.scrollbar.config(command=self.tree.yview)
		self.tree.place(x=0,y=100,height=600,width=970)

	"""
		This function makes graph using pyplot python library, This grah contains name of protocol vs number of packets 
		and average packets.

		@paaram null
		@return null
	"""	
	def make_protocol_table_graph(self):
		self.printLog("UI/UX","window","Graph initiated")
		self.printLog("System","pyplot","")
		plt.plot(list(self.protos),list(self.protos.values()) , label = "Frequency",color='green', linestyle='dashed', linewidth = 1, marker='o', markerfacecolor='blue', markersize=8)
		plt.plot(list(self.protos),[ i/self.total_time for i in list(self.protos.values()) ] , label = "Average Frequency",color='orange')  
		plt.xlabel('Frequency') 
		plt.ylabel('Protocols') 
		plt.title('Protocol vs Frequency and Average Frequency') 
		plt.legend() 
		plt.show()
		self.printLog("UI/UX","window","Graph terminated")
		pass

	"""
		This function will print the tanle with 2 coloumns. First coloumn for sender's mac address taken from Ethernet packet
		ans 2nd coloumn for number of packet sent by this mac address.

		@param null
		@return null
	"""
	def make_distrution_table(self):
		currdir = os.getcwd()
		self.printLog("Ui/UX","wondow","selecting file from system")
		self.filename =  filedialog.asksaveasfilename(parent=self,initialdir =currdir,title = "Select file",filetypes = (("Pcap files","*.pcap"),("all files","*.*")))
		if self.filename!=():
			self.printLog("FileSystem","pcap file",self.filename)
		else:
			self.printLog("FileSystem","Error","File not entered...")
			self.printLog("System","Exit","")
			exit(0)

		self.printLog("FileSystem","Read","data reading from file")	
		self.frames = anl.readFile(self.filename)
		self.printLog("System","Process","counting total time interval")
		self.total_time = anl.get_time_pcap_file(self.frames)
		self.printLog("System","Process","counting frquancy of each protocol")
		self.protos = anl.get_all_prot_used_with_frq(self.frames)

		try:
			self.graphButton.destroy()
		except:
			pass

		self.graphButton = Button(self, text="generate graph",command=self.make_distrution_table_graph )
		self.graphButton.place(x=700, y=120)

		self.protocol_to_frames=anl.get_protocol_to_frames(self.frames)

		self.variable = StringVar(self)
		self.variable.set("Select the protocol")

		self.opt=OptionMenu(self, self.variable, "Select the protocol" ,*self.protos)
		self.opt.config(width=102, font=('Helvetica', 12))
		self.opt.place(x=0,y=50)

		try:
			if self.tree != None:
				self.tree.destroy()
			if self.scrollbar != None:
				self.scrollbar.destroy()
		except:
			pass

		self.printLog("UI/UX","window","Select bar and filter is showing")
		self.scrollbar = ttk.Scrollbar(self)
		self.column_names = ("Source MAC","Frequency","Average Frequency")
		self.tree = ttk.Treeview(self, columns = self.column_names, yscrollcommand = self.scrollbar.set)
		self.scrollbar.pack(side = 'right', fill= Y)
		self.variable.trace("w",self.opt_callback)
		self.tree['show'] = 'headings'

		self.lab_flt = Label(self,text="Filter : Minimum packets")
		self.lab_flt.place(x=0,y=100)

		self.flt=Entry(self)
		self.flt.place(x=0,y=125)
		self.flt.insert(END, '0')

		self.avg_lab_flt = Label(self,text="Filter : Minimum average packets")
		self.avg_lab_flt.place(x=200,y=100)

		self.avg_flt=Entry(self)
		self.avg_flt.place(x=200,y=125)
		self.avg_flt.insert(END, '0')

		self.but_apply=Button(self,text="Apply",command=self.filter_apply)
		self.but_apply.place(x=400,y=120)

	"""
		This function will filter out the query given by the user and shows in the table form.

		@param null
		@return null
	"""
	def filter_apply(self):
		try:
			self.printLog("System","Filter","Filter processing start")
			self.flt_val=int(eval(self.flt.get()))
			self.avg_flt_val=float(eval(self.avg_flt.get()))
			self.printLog("System","Filter value",self.avg_flt_val)
			rt=self.variable.get()
			self.printLog("System","Option selectd",rt)
			self.choosan_name = rt
			if rt == 'Select the protocol':
				return	
			self.src_addr=anl.get_all_src_addr(rt)
			treedata = []
			self.printLog("System","Write","data is appending in table")
			for addr in self.src_addr:
				if int(self.src_addr[addr]) >= int(self.flt_val) and float(self.src_addr[addr]/self.total_time) >= float(self.avg_flt_val): 
					treedata.append((addr,self.src_addr[addr],self.src_addr[addr]/self.total_time))
			self.tree.delete(*self.tree.get_children())
			for col in self.column_names: 
				self.tree.heading(col, text = col)
			for x in treedata:
				self.tree.insert('', 'end', values=x)
			self.scrollbar.config(command=self.tree.yview)
			self.tree.place(x=0,y=150,height=550,width=970)
		except:
			self.printLog("System","Filter","something is wrong")

	"""
		This is callback funtion for menu bar for selecting the protocols.

		@param *args (default)
		@return null
	"""
	def opt_callback(self,*args):
		rt=self.variable.get()
		self.printLog("System","Option selectd",rt)
		self.choosan_name = rt
		if rt == 'Select the protocol':
			return	
		self.src_addr=anl.get_all_src_addr(rt)

		treedata = []

		self.printLog("System","Write","data is appending in table")
		for addr in self.src_addr:
			treedata.append((addr,self.src_addr[addr],self.src_addr[addr]/self.total_time))

		self.tree.delete(*self.tree.get_children())
		for col in self.column_names: 
			self.tree.heading(col, text = col)
		for x in treedata:
			self.tree.insert('', 'end', values=x)
		self.scrollbar.config(command=self.tree.yview)
		self.tree.place(x=0,y=150,height=550,width=970)

	"""
		This function makes graph using pyplot python library, This grah contains senders mac address vs number of packets by this mac address

		@paaram null
		@return null
	"""	
	def make_distrution_table_graph(self):
		if self.src_addr != None:
			x_list=list()
			y_list=list()
			y_avg=list()
			y_thr=list()
			y_avg_thr=list()
			self.printLog("UI/UX","window","Graph initiated")
			self.printLog("System","pyplot","")
			for sd in self.src_addr:
				if int( self.src_addr[sd] ) >= self.flt_val and float(self.src_addr[sd]/self.total_time) >= float(self.avg_flt_val):
					x_list.append(sd)
					y_list.append(self.src_addr[sd])
					y_avg.append(float(self.src_addr[sd]/self.total_time))
					y_thr.append(self.flt_val)
					y_avg_thr.append(self.avg_flt_val)

			plt.plot(x_list, y_list , label = "Number of packets",color='green', linestyle='dashed', linewidth = 1, marker='o', markerfacecolor='blue', markersize=8)
			plt.plot(x_list, y_thr , label = "Minimum packets threshold", color='red')
			plt.plot(x_list, y_avg , label="Average packets",color="orange")
			plt.plot(x_list, y_avg_thr , label = "Average packets threshold", color='blue')

			plt.xlabel('Mac Address') 
			plt.ylabel('Numbers of packets') 
			plt.title(str(self.choosan_name) + ' : Packet vs Sender\'s Mac Address') 
			plt.legend()
			plt.show()
			self.printLog("UI/UX","window","Graph terminated")
		else:
			self.printLog("System","process","Something is wrong with making Intrusion table")

def main():
	root = Tk()
	root.geometry("1000x700")
	app = Window(root)
	root.mainloop() 

if __name__ == '__main__':
	main()