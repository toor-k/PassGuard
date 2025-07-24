import tkinter as tk
from tkinter import ttk
import string
import math
class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Advanced Password Strength Checker")
        self.geometry("650x650")
        # Configure styles
        self.style = ttk.Style()
        self.style.configure("TFrame", background="#ffffff")
        self.style.configure("TLabel", background="#ffffff")
        self.style.configure("TCheckbutton", background="#ffffff")
        # Main frame
        main_frame = ttk.Frame(self, padding="15")
        main_frame.pack(fill=tk.BOTH, expand=True)
        # Title
        ttk.Label(main_frame, text="Password Strength Analyzer", 
                 font=("Arial", 14, "bold")).pack(pady=(0, 15))
        #input
        ttk.Label(main_frame, text="Enter Password:", font=("Arial", 11)).pack(anchor=tk.W, pady=(0, 5))
        input_frame = ttk.Frame(main_frame)
        input_frame.pack(fill=tk.X, pady=(0, 10))
        self.password_var = tk.StringVar()
        self.entry = ttk.Entry(input_frame, show="*", textvariable=self.password_var, 
                              width=40, font=("Arial", 11))
        self.entry.pack(side=tk.LEFT, padx=(0, 10))
        self.entry.bind("<KeyRelease>", self.on_change)
        self.entry.focus()  # Focus on entry field by default
        # Show password toggle
        self.show_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(input_frame, text="Show", variable=self.show_var, 
                       command=self.toggle_show).pack(side=tk.LEFT)
        # Copy button
        ttk.Button(input_frame, text="Copy", command=self.copy_password).pack(side=tk.RIGHT)
        # Strength visualization frame
        strength_frame = ttk.LabelFrame(main_frame, text="Strength Analysis", padding="10")
        strength_frame.pack(fill=tk.X, pady=(0, 15))
        # Strength bar with improved styling
        self.bar_frame = ttk.Frame(strength_frame, height=25)
        self.bar_frame.pack(fill=tk.X, pady=(0, 10))
        self.bar_frame.pack_propagate(False)
        self.bar = tk.Canvas(self.bar_frame, bg="#f0f0f0", highlightthickness=1, 
                           highlightbackground="#cccccc", relief="solid", bd=1)
        self.bar.pack(fill=tk.BOTH, expand=True)
        self.bar.fill = self.bar.create_rectangle(0, 0, 0, 25, fill="red", width=0)
        # Strength label with better styling
        self.str_label = ttk.Label(strength_frame, text="", font=("Arial", 12, "bold"))
        self.str_label.pack(anchor=tk.W, pady=(0, 10))
        # Options frame
        options_frame = ttk.Frame(strength_frame)
        options_frame.pack(fill=tk.X, pady=(0, 10))
        # Entropy toggle
        entropy_frame = ttk.Frame(options_frame)
        entropy_frame.pack(side=tk.LEFT, anchor=tk.W, padx=(0, 20))
        
        self.show_entropy = tk.BooleanVar(value=False)
        self.entropy_toggle = ttk.Checkbutton(entropy_frame, text="Show Entropy", 
                                             variable=self.show_entropy, command=self.toggle_entropy)
        self.entropy_toggle.pack(side=tk.LEFT)
        # Entropy value label (initially hidden)
        self.entropy_label = ttk.Label(entropy_frame, text="", font=("Arial", 10))
        # Crack time estimation toggle
        crack_time_frame = ttk.Frame(options_frame)
        crack_time_frame.pack(side=tk.LEFT, anchor=tk.W)
        self.show_crack_time = tk.BooleanVar(value=False)
        ttk.Checkbutton(crack_time_frame, text="Show Crack Time", 
                       variable=self.show_crack_time, command=self.on_change).pack(side=tk.LEFT)
        # Crack time label (initially hidden)
        self.crack_time_label = ttk.Label(crack_time_frame, text="", font=("Arial", 10))
        # Tips section
        tips_frame = ttk.LabelFrame(main_frame, text="Recommendations", padding="10")
        tips_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 10))
        
        self.tips_label = ttk.Label(tips_frame, text="", font=("Arial", 9), 
                                   foreground="#444444", wraplength=550, justify=tk.LEFT)
        self.tips_label.pack(anchor=tk.NW, fill=tk.BOTH, expand=True)
        # Footer with info
        footer_frame = ttk.Frame(main_frame)
        footer_frame.pack(fill=tk.X, pady=(10, 0))
        footer_text = "Note: This is an estimation based on password entropy and common patterns."
        ttk.Label(footer_frame, text=footer_text, font=("Arial", 8), 
                 foreground="#666666", wraplength=550).pack(side=tk.LEFT)
        # Bind window resize event
        self.bind("<Configure>", self.on_resize)
    def on_resize(self, event):
        """Handle window resize events"""
        if event.widget == self:
            self.on_change()
    def toggle_show(self):
        self.entry.config(show="" if self.show_var.get() else "*")
    def copy_password(self):
        """Copy password to clipboard"""
        password = self.password_var.get()
        if password:
            self.clipboard_clear()
            self.clipboard_append(password)
            # Show temporary confirmation
            original_text = self.entry.get()
            self.entry.delete(0, tk.END)
            self.entry.insert(0, "✓ Copied to clipboard!")
            self.after(1000, lambda: self.entry.delete(0, tk.END) or self.entry.insert(0, original_text))
    def toggle_entropy(self):
        # Show or hide entropy label based on toggle state
        if self.show_entropy.get():
            self.entropy_label.pack(side=tk.LEFT, padx=(10, 0))
        else:
            self.entropy_label.pack_forget()
        self.on_change()
    def calculate_entropy(self, password):
        """Calculate password entropy in bits"""
        if not password:
            return 0 
        # Character pool size estimation
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
        # Assuming 10^9 guesses per second (modern GPU)
        guesses_per_second = 10**9
        total_guesses = 2 ** entropy
        seconds = total_guesses / guesses_per_second
        # Convert to human readable time
        if seconds < 1:
            return "Instantly"
        elif seconds < 60:
            return f"{seconds:.1f} seconds"
        elif seconds < 3600:
            return f"{seconds/60:.1f} minutes"
        elif seconds < 86400:
            return f"{seconds/3600:.1f} hours"
        elif seconds < 31536000:
            return f"{seconds/86400:.1f} days"
        else:
            return f"{seconds/31536000:.1f} years"
    def get_strength_info(self, password):
        """Get password strength information"""
        if not password:
            return 0, "gray", 0, []     
        entropy = self.calculate_entropy(password)
        tips = []
        # Length check
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
            tips.append("Add symbols (e.g., !@#$%)")
        # Common pattern checks
        if password.lower() in ["password", "123456", "qwerty", "letmein"]:
            tips.append("Avoid common passwords")
        elif len(password) < 4:
            tips.append("Password is too short")
        elif password.isdigit():
            tips.append("Avoid using only numbers")
        elif password.isalpha():
            tips.append("Mix letters with numbers or symbols")
        # Map entropy to strength level
        if entropy < 28:
            color = "#ff4d4d"  # red
            strength_label = "Weak"
        elif entropy < 40:
            color = "#ff9933"  # orange
            strength_label = "Fair"
        elif entropy < 60:
            color = "#3399ff"  # blue
            strength_label = "Strong"
        else:
            color = "#33cc33"  # green
            strength_label = "Very Strong"
        return entropy, color, strength_label, tips 
    def on_change(self, event=None):
        password = self.password_var.get()
        if password:
            entropy, color, strength_label, tips = self.get_strength_info(password)
            self.str_label.config(text=f"Strength: {strength_label}", foreground=color)
            # Update bar (cap at 80 bits for visualization)
            bar_width = (min(entropy, 80) / 80) * self.bar.winfo_width()
            if bar_width > 0:  # Only update if we have a width
                self.bar.coords(self.bar.fill, 0, 0, bar_width, 25)
                self.bar.itemconfig(self.bar.fill, fill=color)
            # Show entropy if requested
            if self.show_entropy.get():
                self.entropy_label.config(text=f"Entropy: {entropy:.2f} bits")
            # Show crack time if requested
            if self.show_crack_time.get():
                crack_time = self.estimate_crack_time(entropy)
                self.crack_time_label.config(text=f"Estimated crack time: {crack_time}")
                self.crack_time_label.pack(side=tk.LEFT, padx=(10, 0))
            else:
                self.crack_time_label.pack_forget()    
            # Show tips
            if tips:
                self.tips_label.config(text="• " + "\n• ".join(tips))
            else:
                self.tips_label.config(text="No obvious weaknesses detected. Good job!")
        else:
            self.str_label.config(text="")
            self.entropy_label.config(text="")
            self.crack_time_label.config(text="")
            self.tips_label.config(text="Enter a password to analyze its strength")
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