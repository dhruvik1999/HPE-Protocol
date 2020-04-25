from tkinter import *

window = Tk()
window.title("Protocol Analyzer")
window.geometry('1100x1000')

lbl = Label(window,text="Wellcome to Protocol analyzer",  font=("Arial Bold", 50))
lbl.grid(column=0,row=0)

btn = Button(window, text="Click Me")
btn.grid(column=1, row=5)



window.mainloop()