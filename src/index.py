from tkinter import *
from tkinter import ttk

class Window(Frame):
	def __init__(self, master=None):
		Frame.__init__(self, master)
		self.master = master
		self.init_window()

	def init_window(self):
		self.master.title("GUI")
		self.pack(fill=BOTH, expand=1)
		lbl1 = Label(self,text="Protocol Analyser")
		lbl1.place(x=0,y=0)

		quitButton = Button(self, text="Analys")
		quitButton.place(x=0, y=40)
		quitButton = Button(self, text="Intrution Detection")
		quitButton.place(x=80, y=40)

		self.make_protocol_table()

	def make_protocol_table(self):
		treedata = [('column 1', 'column 2'), ('column 2', 'column 2'),('column 1', 'column 2'),('column 1', 'column 2'),('column 1', 'column 2'),('column 1', 'column 2'),('column 2', 'column 2'),('column 1', 'column 2'),('column 1', 'column 2'),('column 1', 'column 2'),('column 2', 'column 2'),('column 1', 'column 2'),('column 2', 'column 2'),('column 1', 'column 2'),('column 1', 'column 2'),('column 1', 'column 2'),('column 2', 'column 2'),('column 1', 'column 2'),('column 1', 'column 2'),('column 1', 'column 2'),('column 2', 'column 2')]
		column_names = ("heading1", "heading2")
		scrollbar = ttk.Scrollbar(self)
		tree = ttk.Treeview(self, columns = column_names, yscrollcommand = scrollbar.set)
		scrollbar.pack(side = 'right', fill= Y)

		for x in treedata:
			tree.insert('', 'end', values=x)
		for col in column_names: 
			tree.heading(col, text = "Title")
		scrollbar.config(command=tree.yview)
		tree.place(x=0,y=100)

root = Tk()
root.geometry("1000x1000")
app = Window(root)
root.mainloop() 