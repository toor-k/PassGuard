
import tkinter as tk
from tkinter import ttk
import string
import math

class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Password Strength Checker")
        self.geometry("600x550")
        # Password input
        ttk.Label(self, text="Enter Password:").pack(pady=10)
        self.password_var = tk.StringVar()
        self.entry = ttk.Entry(self, show="*", textvariable=self.password_var, width=40)
        self.entry.pack()
        self.entry.bind("<KeyRelease>", self.on_change)
        # Strength bar
        self.bar = tk.Canvas(self, width=400, height=20, bg="#e8e8e8", highlightthickness=0)
        self.bar.pack(pady=5)
        self.bar.create_rectangle(0,0,0,20, fill="green", tags="bar") 
        # Strength label
        self.str_label = ttk.Label(self, text="", font=("Arial", 12))
        self.str_label.pack(pady=5) 
        # El calcula V1
        self.show_entropy = tk.BooleanVar(value=False)
        ttk.Checkbutton(self, text="Show Entropy", variable=self.show_entropy, 
                       command=self.on_change).pack()
        
        #label
        self.entropy_label = ttk.Label(self, text="")
        self.entropy_label.pack(pady=5)
    def calculate_entropy(self, password):
        """Calculate password entropy in bits"""
        if not password:
            return 0   
        #size estimation
        pool_size = 0
        if any(c.islower() for c in password): pool_size += 26
        if any(c.isupper() for c in password): pool_size += 26
        if any(c.isdigit() for c in password): pool_size += 10
        if any(not c.isalnum() for c in password): pool_size += 32
        if pool_size == 0:
            return 0
        return len(password) * math.log2(pool_size)
    def calculate_strength(self, password):
        """Password strength calculation with entropy"""
        if not password:
            return 0, "gray", 0
        entropy = self.calculate_entropy(password)
        if entropy < 28:
            return entropy, "red", entropy
        elif entropy < 40:
            return entropy, "orange", entropy
        elif entropy < 60:
            return entropy, "blue", entropy
        else:
            return entropy, "green", entropy
        
    def on_change(self, event=None):
        password = self.password_var.get()
        if password:
            strength, color, entropy = self.calculate_strength(password)
            self.str_label.config(text=f"Strength: {strength:.1f} bits", foreground=color)
            
            # bar cap 80b
            bar_len = (min(entropy, 80) / 80) * 400
            self.bar.coords("bar", 0, 0, bar_len, 20)
            self.bar.itemconfig("bar", fill=color)
            
            if self.show_entropy.get():
                self.entropy_label.config(text=f"Entropy: {entropy:.2f} bits")
            else:
                self.entropy_label.config(text="")
        else:
            self.str_label.config(text="")
            self.entropy_label.config(text="")
            self.bar.coords("bar", 0, 0, 0, 20)
if __name__ == "__main__":
    app = App()
    app.mainloop()