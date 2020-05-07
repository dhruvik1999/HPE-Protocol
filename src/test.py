from tkinter import *
from tkinter import ttk

root = Tk()
treedata = [('column 1', 'column 2'), ('column 1', 'column 2'),('column 1', 'column 2'),('column 1', 'column 2'),('column 1', 'column 2'),('column 1', 'column 2'),('column 1', 'column 2'),('column 1', 'column 2'),('column 1', 'column 2'),('column 1', 'column 2'),('column 1', 'column 2'),('column 1', 'column 2'),('column 1', 'column 2'),('column 1', 'column 2'),('column 1', 'column 2'),('column 1', 'column 2'),('column 1', 'column 2'),('column 1', 'column 2'),('column 1', 'column 2'),('column 1', 'column 2'),('column 1', 'column 2')]
column_names = ("heading1", "heading2")
scrollbar = ttk.Scrollbar(root)
tree = ttk.Treeview(root, columns = column_names, yscrollcommand = scrollbar.set)
scrollbar.pack(side = 'right', fill= Y)

for x in treedata:
    tree.insert('', 'end', values =x)
for col in column_names: 
    tree.heading(col, text = "Title")
scrollbar.config(command=tree.yview)
tree.pack()
root.mainloop()