import tkinter as tk
from tkinter import ttk
import string
import math
class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Password Strength Checker")
        self.geometry("600x600")
        main_frame = ttk.Frame(self, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)
        ttk.Label(main_frame, text="Enter Password:", font=("Arial", 12)).pack(pady=10)
        input_frame = ttk.Frame(main_frame)
        input_frame.pack(fill=tk.X, pady=5) 
        self.password_var = tk.StringVar()
        self.entry = ttk.Entry(input_frame, show="*", textvariable=self.password_var, width=40, font=("Arial", 11))
        self.entry.pack(side=tk.LEFT, padx=(0, 10))
        self.entry.bind("<KeyRelease>", self.on_change)
        self.show_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(input_frame, text="Show", variable=self.show_var, command=self.toggle_show).pack(side=tk.LEFT)
        strength_frame = ttk.Frame(main_frame)
        strength_frame.pack(fill=tk.X, pady=10)
        ttk.Label(strength_frame, text="Password Strength:", font=("Arial", 10)).pack(anchor=tk.W)
        self.bar_frame = ttk.Frame(strength_frame, height=25)
        self.bar_frame.pack(fill=tk.X, pady=5)
        self.bar_frame.pack_propagate(False)
        self.bar = tk.Canvas(self.bar_frame, bg="#f0f0f0", highlightthickness=1, highlightbackground="#cccccc")
        self.bar.pack(fill=tk.BOTH, expand=True)
        self.bar.fill = self.bar.create_rectangle(0, 0, 0, 25, fill="red", width=0)
        self.str_label = ttk.Label(strength_frame, text="", font=("Arial", 12, "bold"))
        self.str_label.pack(pady=5)
        options_frame = ttk.Frame(main_frame)
        options_frame.pack(fill=tk.X, pady=10)
        entropy_frame = ttk.Frame(options_frame)
        entropy_frame.pack(anchor=tk.W, pady=5)
        self.show_entropy = tk.BooleanVar(value=False)
        self.entropy_toggle = ttk.Checkbutton(entropy_frame, text="Show Entropy", variable=self.show_entropy, 
                                             command=self.toggle_entropy)
        self.entropy_toggle.pack(side=tk.LEFT)
        
        self.entropy_label = ttk.Label(entropy_frame, text="", font=("Arial", 10))
        self.show_crack_time = tk.BooleanVar(value=False)
        ttk.Checkbutton(options_frame, text="Show Crack Time Estimate", variable=self.show_crack_time, 
                       command=self.on_change).pack(anchor=tk.W, pady=5)
        
        # Crack time label (initially hidden)
        self.crack_time_label = ttk.Label(options_frame, text="", font=("Arial", 10))
        #Tips
        ttk.Label(main_frame, text="Tips:", font=("Arial", 10, "bold")).pack(anchor=tk.W, pady=(15, 5))
        self.tips_label = ttk.Label(main_frame, text="", font=("Arial", 9), foreground="#666666", wraplength=500)
        self.tips_label.pack(anchor=tk.W, fill=tk.X)
        
    def toggle_show(self):
        self.entry.config(show="" if self.show_var.get() else "*")
        
    def toggle_entropy(self):
        #show or hide entropy label based on toggle state
        if self.show_entropy.get():
            self.entropy_label.pack(side=tk.LEFT, padx=(10, 0))
        else:
            self.entropy_label.pack_forget()
        self.on_change()
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
    def estimate_crack_time(self, entropy):
        """Estimate time to crack password based on entropy"""
        if entropy <= 0:
            return "Instantly"
        #Assuming 10^9 guesses per second (modern GPU)
        guesses_per_second = 10**9
        total_guesses = 2 ** entropy
        seconds = total_guesses / guesses_per_second
        if seconds < 60:
            return "Less than a minute"
        elif seconds < 3600:
            return f"About {int(seconds/60)} minutes"
        elif seconds < 86400:
            return f"About {int(seconds/3600)} hours"
        elif seconds < 31536000:
            return f"About {int(seconds/86400)} days"
        else:
            return f"About {int(seconds/31536000)} years"
    def get_strength_info(self, password):
        """Get password strength information"""
        if not password:
            return 0, "gray", 0, []    
        entropy = self.calculate_entropy(password)
        tips = []
        #Length check
        if len(password) < 8:
            tips.append("Use at least 8 characters")
        elif len(password) < 12:
            tips.append("Consider using 12+ characters for better security")
        # Character variety checks
        if not any(c.islower() for c in password):
            tips.append("Add lowercase letters")
        if not any(c.isupper() for c in password):
            tips.append("Add uppercase letters")
        if not any(c.isdigit() for c in password):
            tips.append("Add numbers")
        if not any(not c.isalnum() for c in password):
            tips.append("Add symbols")
        # Map entropy to strength level
        if entropy < 28:
            color = "red"
            strength_label = "Weak"
        elif entropy < 40:
            color = "orange"
            strength_label = "Fair"
        elif entropy < 60:
            color = "blue"
            strength_label = "Strong"
        else:
            color = "green"
            strength_label = "Very Strong"
        return entropy, color, strength_label, tips
    def on_change(self, event=None):
        password = self.password_var.get()
        if password:
            entropy, color, strength_label, tips = self.get_strength_info(password)
            self.str_label.config(text=f"Strength: {strength_label}", foreground=color) 
            # cap 80b
            bar_width = (min(entropy, 80) / 80) * self.bar.winfo_width()
            if bar_width > 0:  # Only update if we have a width
                self.bar.coords(self.bar.fill, 0, 0, bar_width, 25)
                self.bar.itemconfig(self.bar.fill, fill=color)

            if self.show_entropy.get():
                self.entropy_label.config(text=f"Entropy: {entropy:.2f} bits")
            if self.show_crack_time.get():
                crack_time = self.estimate_crack_time(entropy)
                self.crack_time_label.config(text=f"Estimated crack time: {crack_time}")
                self.crack_time_label.pack(anchor=tk.W, pady=5)
            else:
                self.crack_time_label.pack_forget()
                
            #tips
            if tips:
                self.tips_label.config(text="• " + "\n• ".join(tips))
            else:
                self.tips_label.config(text="No obvious weaknesses detected")
        else:
            self.str_label.config(text="")
            self.entropy_label.config(text="")
            self.crack_time_label.config(text="")
            self.tips_label.config(text="")
            self.bar.coords(self.bar.fill, 0, 0, 0, 25)
            self.crack_time_label.pack_forget()
        self.after(100, self.update_bar)    
    def update_bar(self):
        """Update the bar width based on current window size"""
        if self.password_var.get():
            password = self.password_var.get()
            entropy, color, strength_label, tips = self.get_strength_info(password)
            bar_width = (min(entropy, 80) / 80) * self.bar.winfo_width()
            self.bar.coords(self.bar.fill, 0, 0, bar_width, 25)
if __name__ == "__main__":
    app = App()
    app.mainloop()