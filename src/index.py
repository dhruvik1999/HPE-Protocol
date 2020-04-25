from tkinter import *
from tkinter import filedialog
import os
import analyser

window = Tk()
window.title("Protocol Analyzer")
window.geometry('1100x1000')

lbl = Label(window,text="Protocol Analyzer",  font=("Arial Bold", 20))
lbl.grid(column=0,row=0)

def search_for_file_path ():
	currdir = os.getcwd()
	tempdir = filedialog.askopenfilename(parent=window, initialdir=currdir, title='Please select a directory')
	if len(tempdir) > 0:
		print ("File : %s" % tempdir)
		L2 = Label(window, text="FILE : "+tempdir,).grid(row=5,column=0)
		return tempdir
	return None

def analyse():
	file_path_variable = search_for_file_path()
	frames = analyser.readFile(file_path_variable)
	analyser.disp_prot_details(frames)


B=Button(window, text ="Analyse",command=analyse).grid(row=3,column=0,)

window.mainloop()