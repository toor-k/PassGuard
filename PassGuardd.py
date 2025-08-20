import tkinter as tk
from tkinter import ttk
class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Password Strength Checker")
        self.geometry("700x400")   
        ## input
        ttk.Label(self, text="Enter Password:").pack(pady=10)
        self.password_var = tk.StringVar()
        self.entry = ttk.Entry(self, show="*", textvariable=self.password_var, width=40)
        self.entry.pack()
        self.entry.bind("<KeyRelease>", self.on_change)
        
        #Strength label
        self.str_label = ttk.Label(self, text="", font=("Arial", 12))
        self.str_label.pack(pady=10)
        
    def on_change(self, event):
        #Plaecholder for strength checking
        password = self.password_var.get()
        if password:
            self.str_label.config(text="Strength: Checking...")
        else:
            self.str_label.config(text="")
if __name__ == "__main__":
    app = App()
    app.mainloop()