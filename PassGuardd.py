import tkinter as tk
from tkinter import ttk
import string

class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Password Strength Checker")
        self.geometry("600x500")
        
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
        
    def calculate_strength(self, password):
        """Basic password strength calculation"""
        if not password:
            return 0, "gray"
            
        score = 0
        # Length
        if len(password) >= 8:
            score += 1
        if len(password) >= 12:
            score += 1
            
        # Character variety
        has_lower = any(c.islower() for c in password)
        has_upper = any(c.isupper() for c in password)
        has_digit = any(c.isdigit() for c in password)
        has_symbol = any(not c.isalnum() for c in password)
        
        if has_lower: score += 1
        if has_upper: score += 1
        if has_digit: score += 1
        if has_symbol: score += 1
        
        # Determine strength level
        if score <= 2:
            return score, "red"
        elif score <= 4:
            return score, "orange"
        elif score <= 6:
            return score, "blue"
        else:
            return score, "green"
        
    def on_change(self, event):
        password = self.password_var.get()
        if password:
            score, color = self.calculate_strength(password)
            self.str_label.config(text=f"Strength: {score}/8", foreground=color)
            
            # Update bar
            bar_len = (score / 8) * 400
            self.bar.coords("bar", 0, 0, bar_len, 20)
            self.bar.itemconfig("bar", fill=color)
        else:
            self.str_label.config(text="")
            self.bar.coords("bar", 0, 0, 0, 20)

if __name__ == "__main__":
    app = App()
    app.mainloop()