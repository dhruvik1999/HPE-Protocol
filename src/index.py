from tkinter import *
from tkinter import ttk
from tkinter import filedialog
import analyser as anl

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

	def init_window(self):
		self.master.title("GUI")
		self.pack(fill=BOTH, expand=1)
		lbl1 = Label(self,text="Protocol Analyser")
		lbl1.place(x=0,y=0)

		quitButton = Button(self, text="Analys")
		quitButton.place(x=0, y=40)
		quitButton = Button(self, text="Intrution Detection")
		quitButton.place(x=80, y=40)

		currdir = os.getcwd()
		self.filename =  filedialog.asksaveasfilename(parent=self,initialdir =currdir,title = "Select file",filetypes = (("jpeg files","*.pcap"),("all files","*.*")))
		if self.filename!=():
			print (self.filename)
		else:
			print("File not inserted...")
			exit(0)

		self.make_distrution_table()

	def make_protocol_table(self):
		self.frames = anl.readFile(self.filename)
		self.total_time = anl.get_time_pcap_file(self.frames)
		self.protos = anl.get_all_prot_used_with_frq(self.frames)
		print(self.protos)
		treedata = []

		for proto in self.protos:
			treedata.append( ( proto , self.protos[proto] ,self.protos[proto]/self.total_time) )

		column_names = ("Protocols", "Frequancy","Average Frq")
		scrollbar = ttk.Scrollbar(self)
		tree = ttk.Treeview(self, columns = column_names, yscrollcommand = scrollbar.set)
		scrollbar.pack(side = 'right', fill= Y)

		for col in column_names: 
			tree.heading(col, text = col)
		for x in treedata:
			tree.insert('', 'end', values=x)
		scrollbar.config(command=tree.yview)
		tree.place(x=0,y=100,height=600,width=900)

	def make_distrution_table(self):
		self.frames = anl.readFile(self.filename)
		self.total_time = anl.get_time_pcap_file(self.frames)
		self.protos = anl.get_all_prot_used_with_frq(self.frames)
		print(self.protos)

		self.protocol_to_frames=anl.get_protocol_to_frames(self.frames)
		print("-->",self.protocol_to_frames)
		# anl.protocol_to_frames=self.protocol_to_frames
		# print( anl.get_all_src_addr('TCP') )
		self.variable = StringVar(self)
		self.variable.set(self.protos)

		opt=OptionMenu(self, self.variable, *self.protos)
		opt.config(width=90, font=('Helvetica', 12))
		opt.place(x=0,y=100)

		self.variable.trace("w",self.opt_callback)

	def opt_callback(self,*args):
		rt=self.variable.get()
		print(rt)
		src_addr=anl.get_all_src_addr(rt)

		treedata = []
		for addr in src_addr:
			treedata.append((addr,src_addr[addr]))

		column_names = ("Source MAC","Frequancy")
		scrollbar = ttk.Scrollbar(self)
		tree = ttk.Treeview(self, columns = column_names, yscrollcommand = scrollbar.set)
		scrollbar.pack(side = 'right', fill= Y)

		for col in column_names: 
			tree.heading(col, text = col)
		for x in treedata:
			tree.insert('', 'end', values=x)
		scrollbar.config(command=tree.yview)
		tree.place(x=0,y=150,height=600,width=900)


root = Tk()
root.geometry("1000x1000")
app = Window(root)
root.mainloop() 