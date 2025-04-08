import pandas as pd
import tkinter as tk
from tkinter import ttk, scrolledtext, filedialog, messagebox
import threading
from ai_analyzer import NetworkAIAnalyzer

class NetworkAIAnalyzerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Network AI Security Analyzer")
        self.root.geometry("900x700")
        self.root.minsize(800, 600)
        
        # Initialize AI Analyzer
        self.analyzer = NetworkAIAnalyzer()
        self.df = None
        
        # Create UI elements
        self.create_ui()
    
    def create_ui(self):
        # Create main frame
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # File selection area
        file_frame = ttk.LabelFrame(main_frame, text="Log File", padding="5")
        file_frame.pack(fill=tk.X, padx=5, pady=5)
        
        self.file_path = tk.StringVar()
        ttk.Entry(file_frame, textvariable=self.file_path, width=50).pack(side=tk.LEFT, padx=5, expand=True, fill=tk.X)
        ttk.Button(file_frame, text="Browse", command=self.browse_file).pack(side=tk.LEFT, padx=5)
        ttk.Button(file_frame, text="Load", command=self.load_file).pack(side=tk.LEFT, padx=5)
        
        # Analysis options
        options_frame = ttk.LabelFrame(main_frame, text="Analysis Options", padding="5")
        options_frame.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Label(options_frame, text="Sample Size:").pack(side=tk.LEFT, padx=5)
        self.sample_size = tk.StringVar(value="10")
        ttk.Entry(options_frame, textvariable=self.sample_size, width=5).pack(side=tk.LEFT, padx=5)
        
        ttk.Button(options_frame, text="Analyze Logs", command=self.run_log_analysis).pack(side=tk.LEFT, padx=5)
        ttk.Button(options_frame, text="Identify Attack Patterns", command=self.run_attack_analysis).pack(side=tk.LEFT, padx=5)
        
        # Failure reason analysis
        failure_frame = ttk.LabelFrame(main_frame, text="Explain Failure Reason", padding="5")
        failure_frame.pack(fill=tk.X, padx=5, pady=5)
        
        self.failure_reason = tk.StringVar()
        ttk.Entry(failure_frame, textvariable=self.failure_reason, width=70).pack(side=tk.LEFT, padx=5, expand=True, fill=tk.X)
        ttk.Button(failure_frame, text="Explain", command=self.explain_failure).pack(side=tk.LEFT, padx=5)
        
        # Results area
        results_frame = ttk.LabelFrame(main_frame, text="Analysis Results", padding="5")
        results_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        self.results_text = scrolledtext.ScrolledText(results_frame, wrap=tk.WORD, width=80, height=20)
        self.results_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Status bar
        self.status_var = tk.StringVar()
        status_bar = ttk.Label(self.root, textvariable=self.status_var, relief=tk.SUNKEN, anchor=tk.W)
        status_bar.pack(side=tk.BOTTOM, fill=tk.X)
        self.status_var.set("Ready")
    
    def browse_file(self):
        file_path = filedialog.askopenfilename(filetypes=[("CSV Files", "*.csv"), ("All Files", "*.*")])
        if file_path:
            self.file_path.set(file_path)
    
    def load_file(self):
        file_path = self.file_path.get()
        if not file_path:
            messagebox.showerror("Error", "Please select a file first")
            return
        
        try:
            self.status_var.set("Loading file...")
            self.root.update_idletasks()
            
            self.df = pd.read_csv(file_path)
            messagebox.showinfo("Success", f"Loaded {len(self.df)} records")
            self.status_var.set(f"Loaded {len(self.df)} records from {file_path}")
            
            # Show data sample
            self.results_text.delete(1.0, tk.END)
            self.results_text.insert(tk.END, "Data Sample:\n\n")
            self.results_text.insert(tk.END, self.df.head().to_string())
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load file: {str(e)}")
            self.status_var.set("Error loading file")
    
    def run_log_analysis(self):
        if self.df is None:
            messagebox.showerror("Error", "Please load a file first")
            return
        
        try:
            sample_size = int(self.sample_size.get())
        except ValueError:
            messagebox.showerror("Error", "Sample size must be a number")
            return
        
        self.status_var.set("Analyzing logs...")
        self.root.update_idletasks()
        
        # Run analysis in a separate thread to keep UI responsive
        threading.Thread(target=self._run_log_analysis_thread, args=(sample_size,), daemon=True).start()
    
    def _run_log_analysis_thread(self, sample_size):
        try:
            result = self.analyzer.analyze_logs(self.df, sample_size)
            
            if result['status'] == 'success':
                self.root.after(0, self._update_results, "LOG ANALYSIS RESULTS", result['analysis'])
                self.root.after(0, self._update_status, f"Analysis completed with {result['sample_size']} samples")
            else:
                self.root.after(0, self._show_error, f"Analysis failed: {result['error']}")
        except Exception as e:
            self.root.after(0, self._show_error, f"Error during analysis: {str(e)}")
    
    def run_attack_analysis(self):
        if self.df is None:
            messagebox.showerror("Error", "Please load a file first")
            return
        
        self.status_var.set("Identifying attack patterns...")
        self.root.update_idletasks()
        
        # Run analysis in a separate thread
        threading.Thread(target=self._run_attack_analysis_thread, daemon=True).start()
    
    def _run_attack_analysis_thread(self):
        try:
            result = self.analyzer.identify_attack_patterns(self.df)
            
            if result['status'] == 'success':
                self.root.after(0, self._update_results, "ATTACK PATTERN ANALYSIS", result['attack_analysis'])
                self.root.after(0, self._update_status, "Attack pattern analysis completed")
            else:
                self.root.after(0, self._show_error, f"Analysis failed: {result['error']}")
        except Exception as e:
            self.root.after(0, self._show_error, f"Error during analysis: {str(e)}")
    
    def explain_failure(self):
        failure_text = self.failure_reason.get()
        if not failure_text:
            messagebox.showerror("Error", "Please enter a failure reason")
            return
        
        self.status_var.set("Generating explanation...")
        self.root.update_idletasks()
        
        # Run explanation in a separate thread
        threading.Thread(target=self._explain_failure_thread, args=(failure_text,), daemon=True).start()
    
    def _explain_failure_thread(self, failure_text):
        try:
            result = self.analyzer.explain_failure_reason(failure_text)
            
            if result['status'] == 'success':
                self.root.after(0, self._update_results, "FAILURE EXPLANATION", result['explanation'])
                self.root.after(0, self._update_status, "Explanation generated")
            else:
                self.root.after(0, self._show_error, f"Explanation failed: {result['error']}")
        except Exception as e:
            self.root.after(0, self._show_error, f"Error generating explanation: {str(e)}")
    
    def _update_results(self, title, text):
        self.results_text.delete(1.0, tk.END)
        self.results_text.insert(tk.END, f"=== {title} ===\n\n")
        self.results_text.insert(tk.END, text)
    
    def _update_status(self, status):
        self.status_var.set(status)
    
    def _show_error(self, message):
        messagebox.showerror("Error", message)
        self.status_var.set("Error occurred")

if __name__ == "__main__":
    root = tk.Tk()
    app = NetworkAIAnalyzerApp(root)
    root.mainloop()
