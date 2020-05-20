from tkinter import *
from tkinter import ttk
from tkinter import filedialog
import analyser as anl
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

	def init_window(self):
		self.master.title("GUI")
		self.pack(fill=BOTH, expand=1)
		lbl1 = Label(self,text="Protocol Analyser")
		lbl1.place(x=0,y=0)

		quitButton = Button(self, text="Analys", command=self.make_protocol_table)
		quitButton.place(x=0, y=40)
		quitButton = Button(self, text="Intrution Detection",command=self.make_distrution_table)
		quitButton.place(x=80, y=40)

	def make_protocol_table(self):
		currdir = os.getcwd()
		self.filename =  filedialog.asksaveasfilename(parent=self,initialdir =currdir,title = "Select file",filetypes = (("Pcap files","*.pcap"),("all files","*.*")))
		if self.filename!=():
			print (self.filename)
		else:
			print("File not inserted...")
			exit(0)

		print("->>",self.filename)
		self.frames = anl.readFile(self.filename)
		self.total_time = anl.get_time_pcap_file(self.frames)
		self.protos = anl.get_all_prot_used_with_frq(self.frames)
		# print(self.protos)
		treedata = []

		try:
			self.graphButton.destroy()
		except:
			pass

		self.graphButton = Button(self, text="Genrate graph",command=self.make_protocol_table_graph )
		self.graphButton.place(x=700, y=40)

		for proto in self.protos:
			treedata.append( ( proto , self.protos[proto] ,self.protos[proto]/self.total_time) )

		column_names = ("Protocols", "Frequancy","Average Frq")
		
		print(self.tree)
		try:
			self.tree.destroy()
			self.opt.destroy()
			self.scrollbar.destroy()
		except:
			pass

		self.scrollbar = ttk.Scrollbar(self)
		self.tree = ttk.Treeview(self, columns = column_names, yscrollcommand = self.scrollbar.set)
		self.scrollbar.pack(side = 'right', fill= Y)

		for col in column_names: 
			self.tree.heading(col, text = col)
		for x in treedata:
			self.tree.insert('', 'end', values=x)
		self.scrollbar.config(command=self.tree.yview)
		self.tree.place(x=0,y=100,height=600,width=900)
		# tree.delete(*tree.get_children())

	def make_protocol_table_graph(self):
		print(self.protos.keys())
		print(self.protos.values())
		plt.plot(list(self.protos),list(self.protos.values()) , label = "Frequancy")
		plt.plot(list(self.protos),[ i/self.total_time for i in list(self.protos.values()) ] , label = "Average Frequancy")  
		plt.xlabel('') 
		plt.ylabel('Protocol') 
		plt.title('Protocol vs Frequancy and Average Frequancy') 
		plt.legend() 
		plt.show()
		pass

	def make_distrution_table(self):
		currdir = os.getcwd()
		self.filename =  filedialog.asksaveasfilename(parent=self,initialdir =currdir,title = "Select file",filetypes = (("Pcap files","*.pcap"),("all files","*.*")))
		if self.filename!=():
			print (self.filename)
		else:
			print("File not inserted...")
			exit(0)
		self.frames = anl.readFile(self.filename)
		self.total_time = anl.get_time_pcap_file(self.frames)
		self.protos = anl.get_all_prot_used_with_frq(self.frames)
		print(self.protos)

		try:
			self.graphButton.destroy()
		except:
			pass

		self.graphButton = Button(self, text="Genrate graph",command=self.make_distrution_table_graph )
		self.graphButton.place(x=700, y=40)

		self.protocol_to_frames=anl.get_protocol_to_frames(self.frames)
		print("-->",self.protocol_to_frames)
		# anl.protocol_to_frames=self.protocol_to_frames
		# print( anl.get_all_src_addr('TCP') )
		self.variable = StringVar(self)
		self.variable.set("Select the protocol")

		self.opt=OptionMenu(self, self.variable, "Select the protocol" ,*self.protos)
		self.opt.config(width=100, font=('Helvetica', 12))
		self.opt.place(x=0,y=100)

		try:
			self.tree.destroy()
			self.scrollbar.destroy()
		except:
			pass

		self.scrollbar = ttk.Scrollbar(self)
		self.column_names = ("Source MAC","Frequancy")
		self.tree = ttk.Treeview(self, columns = self.column_names, yscrollcommand = self.scrollbar.set)
		self.scrollbar.pack(side = 'right', fill= Y)
		self.variable.trace("w",self.opt_callback)

	def opt_callback(self,*args):
		rt=self.variable.get()
		print(rt)
		self.choosan_name = rt
		if rt == 'Select the protocol':
			return	
		self.src_addr=anl.get_all_src_addr(rt)

		treedata = []
		for addr in self.src_addr:
			treedata.append((addr,self.src_addr[addr]))

		self.tree.delete(*self.tree.get_children())
		for col in self.column_names: 
			self.tree.heading(col, text = col)
		for x in treedata:
			self.tree.insert('', 'end', values=x)
		self.scrollbar.config(command=self.tree.yview)
		self.tree.place(x=0,y=150,height=550,width=900)

	def make_distrution_table_graph(self):
		if self.src_addr != None:
			plt.plot(list(self.src_addr),list(self.src_addr.values()) , label = "Number of packets")
			plt.xlabel('Mac Address') 
			plt.ylabel('Number of packets') 
			plt.title(str(self.choosan_name) + ' : Packet vs Senders Mac Address') 
			plt.legend()
			plt.show()
		else:
			pass

root = Tk()
root.geometry("1000x700")
app = Window(root)
root.mainloop() 