import tkinter as tk
from tkinter import scrolledtext, messagebox, ttk, filedialog
import subprocess
import threading
import queue
import os
import sys
import re
import shlex # For robust command splitting

class WpscanGUI:
    def __init__(self, master):
        self.master = master
        master.title("WPScan GUI")
        master.geometry("1200x900") # Increased window size
        master.resizable(True, True)
        master.grid_rowconfigure(0, weight=1) # Allow notebook to expand vertically
        master.grid_rowconfigure(1, weight=0) # Generated command frame
        master.grid_rowconfigure(2, weight=0) # Buttons frame
        master.grid_rowconfigure(3, weight=0) # Status bar
        master.grid_rowconfigure(4, weight=1) # Output frame to expand vertically
        master.grid_rowconfigure(5, weight=0) # New row for footer (created by, ethical note)
        master.grid_columnconfigure(0, weight=1) # Allow main column to expand horizontally

        self.wpscan_process = None
        self.output_queue = queue.Queue()
        self.search_start_index = "1.0" # For incremental search

        # Configure style for ttk widgets
        self.style = ttk.Style()
        # Change theme here. 'alt', 'default', 'classic', 'vista', 'xpnative', 'winnative' are common built-in themes.
        # 'clam' was the previous one. Let's try 'alt' for a different look.
        self.style.theme_use('alt') 

        # --- Notebook (Tabs) ---
        self.notebook = ttk.Notebook(master)
        self.notebook.grid(row=0, column=0, sticky="nsew", padx=10, pady=10)

        # --- Target Tab ---
        self.target_frame = ttk.Frame(self.notebook, padding="10 10 10 10")
        self.notebook.add(self.target_frame, text="Target")
        self._create_target_tab(self.target_frame)

        # --- Enumeration Tab ---
        self.enumeration_frame = ttk.Frame(self.notebook, padding="10 10 10 10")
        self.notebook.add(self.enumeration_frame, text="Enumeration")
        self._create_enumeration_tab(self.enumeration_frame)

        # --- Brute-Force Tab ---
        self.bruteforce_frame = ttk.Frame(self.notebook, padding="10 10 10 10")
        self.notebook.add(self.bruteforce_frame, text="Brute-Force")
        self._create_bruteforce_tab(self.bruteforce_frame)

        # --- Update & API Tab ---
        self.update_api_frame = ttk.Frame(self.notebook, padding="10 10 10 10")
        self.notebook.add(self.update_api_frame, text="Update & API")
        self._create_update_api_tab(self.update_api_frame)

        # --- Advanced Tab ---
        self.advanced_frame = ttk.Frame(self.notebook, padding="10 10 10 10")
        self.notebook.add(self.advanced_frame, text="Advanced")
        self._create_advanced_tab(self.advanced_frame)

        # --- Generated Command ---
        self.command_frame = ttk.LabelFrame(master, text="Generated WPScan Command", padding="10 10 10 10")
        self.command_frame.grid(row=1, column=0, sticky="ew", padx=10, pady=(0, 10))
        self.command_frame.grid_columnconfigure(0, weight=1)
        self.command_text = scrolledtext.ScrolledText(self.command_frame, height=3, width=80, font=("Consolas", 10), state=tk.DISABLED)
        self.command_text.grid(row=0, column=0, sticky="nsew")
        
        self.command_buttons_frame = ttk.Frame(self.command_frame)
        self.command_buttons_frame.grid(row=0, column=1, sticky="ne", padx=(10,0))
        self.copy_command_button = ttk.Button(self.command_buttons_frame, text="Copy Command", command=self.copy_command)
        self.copy_command_button.pack(pady=2)
        self.generate_command_button = ttk.Button(self.command_buttons_frame, text="Generate Command", command=self.generate_command)
        self.generate_command_button.pack(pady=2)

        # --- Buttons Frame ---
        self.button_frame = ttk.Frame(master, padding="10 0 10 5")
        self.button_frame.grid(row=2, column=0, sticky="ew")

        self.run_button = ttk.Button(self.button_frame, text="Run WPScan", command=self.run_wpscan)
        self.run_button.pack(side=tk.LEFT, padx=5)

        self.clear_button = ttk.Button(self.button_frame, text="Clear Output", command=self.clear_output)
        self.clear_button.pack(side=tk.LEFT, padx=5)

        self.save_output_button = ttk.Button(self.button_frame, text="Save Output", command=self.save_output)
        self.save_output_button.pack(side=tk.LEFT, padx=5)

        # --- Status Bar ---
        self.status_bar = ttk.Label(master, text="Ready", relief=tk.SUNKEN, anchor=tk.W)
        self.status_bar.grid(row=3, column=0, sticky="ew")

        # --- Output Frame ---
        self.output_frame = ttk.LabelFrame(master, text="WPScan Output", padding="10 10 10 10")
        self.output_frame.grid(row=4, column=0, sticky="nsew", padx=10, pady=(0, 10))
        self.output_frame.grid_rowconfigure(1, weight=1) # Make the output_text expand vertically
        self.output_frame.grid_columnconfigure(0, weight=1) # Make the search_frame and output_text expand horizontally

        # Search functionality for output
        self.search_frame = ttk.Frame(self.output_frame)
        self.search_frame.grid(row=0, column=0, sticky="ew", pady=(0, 5))
        self.search_frame.grid_columnconfigure(1, weight=1) # Make search entry expand
        ttk.Label(self.search_frame, text="Search:").grid(row=0, column=0, sticky="w", padx=(0, 5))
        self.search_entry = ttk.Entry(self.search_frame, width=50)
        self.search_entry.grid(row=0, column=1, sticky="ew", padx=(0, 5))
        self.search_entry.bind("<Return>", self.search_output) # Bind Enter key
        ttk.Button(self.search_frame, text="Search", command=self.search_output).grid(row=0, column=2, sticky="e", padx=(0, 5))
        ttk.Button(self.search_frame, text="Clear Search", command=self.clear_search_highlight).grid(row=0, column=3, sticky="e")

        # Set background and foreground for output_text based on the new theme
        # Tkinter's default text widget colors might not perfectly match ttk themes,
        # so we explicitly set them for better contrast.
        self.output_text = scrolledtext.ScrolledText(self.output_frame, wrap=tk.WORD, bg="#2b2b2b", fg="#f0f0f0", font=("Consolas", 10), height=30)
        self.output_text.grid(row=1, column=0, sticky="nsew")
        self.output_text.config(state=tk.DISABLED) # Make it read-only

        # Configure tag for highlighting search results
        self.output_text.tag_configure("highlight", background="yellow", foreground="black")

        # --- Footer Frame (Created by and Ethical Note) ---
        self.footer_frame = ttk.Frame(master, padding="5 0 5 5")
        self.footer_frame.grid(row=5, column=0, sticky="ew")
        self.footer_frame.grid_columnconfigure(0, weight=1) # Allow left side to expand
        self.footer_frame.grid_columnconfigure(1, weight=1) # Allow right side to expand

        self.created_by_label = ttk.Label(self.footer_frame, text="Created by Khedr 0x00", font=("Arial", 8, "italic"))
        self.created_by_label.grid(row=0, column=0, sticky="w", padx=5)

        self.ethical_note_label = ttk.Label(self.footer_frame, 
                                            text="Note: This tool is intended for ethical and responsible use only. Misuse may lead to severe consequences. Always obtain explicit permission before scanning any website.", 
                                            font=("Arial", 8, "italic"),
                                            wraplength=500, # Wrap text for better readability
                                            justify=tk.RIGHT)
        self.ethical_note_label.grid(row=0, column=1, sticky="e", padx=5)


        self.master.protocol("WM_DELETE_WINDOW", self.on_closing)
        self.master.after(100, self.process_queue) # Start checking the queue
        self.generate_command() # Generate initial command on startup

    def _create_input_field(self, parent_frame, label_text, row, entry_name, col=0, width=40, is_checkbox=False, var_name=None, help_text=None, options=None, is_dropdown=False):
        if is_checkbox:
            var = tk.BooleanVar()
            setattr(self, var_name, var)
            chk = ttk.Checkbutton(parent_frame, text=label_text, variable=var, command=self.generate_command)
            chk.grid(row=row, column=col, sticky="w", pady=2)
            if help_text:
                help_button = ttk.Button(parent_frame, text="?", width=2, command=lambda t=help_text: self._show_help_popup(t))
                help_button.grid(row=row, column=col + 1, sticky="w", padx=(5, 0))
            return chk
        elif is_dropdown and options:
            label = ttk.Label(parent_frame, text=label_text)
            label.grid(row=row, column=col, sticky="w", pady=2, padx=(0, 5))
            var = tk.StringVar()
            setattr(self, var_name, var)
            dropdown = ttk.Combobox(parent_frame, textvariable=var, values=options, state="readonly", width=width)
            dropdown.grid(row=row, column=col+1, sticky="ew", pady=2)
            dropdown.set(options[0]) # Set default value
            dropdown.bind("<<ComboboxSelected>>", lambda event: self.generate_command())
            if help_text:
                help_button = ttk.Button(parent_frame, text="?", width=2, command=lambda t=help_text: self._show_help_popup(t))
                help_button.grid(row=row, column=col + 2, sticky="w", padx=(5, 0))
            return dropdown
        else:
            label = ttk.Label(parent_frame, text=label_text)
            label.grid(row=row, column=col, sticky="w", pady=2, padx=(0, 5))
            if entry_name and ("headers_entry" in entry_name or "additional_args_entry" in entry_name): # Use ScrolledText for larger inputs
                entry = scrolledtext.ScrolledText(parent_frame, height=4, width=width, font=("Consolas", 10))
            else:
                entry = ttk.Entry(parent_frame, width=width)
            
            entry.grid(row=row, column=col+1, sticky="ew", pady=2)
            setattr(self, entry_name, entry)
            entry.bind("<KeyRelease>", lambda event: self.generate_command()) # Update command on key release
            if help_text:
                help_button = ttk.Button(parent_frame, text="?", width=2, command=lambda t=help_text: self._show_help_popup(t))
                help_button.grid(row=row, column=col + 2, sticky="w", padx=(5, 0))
            return entry

    def _show_help_popup(self, help_text):
        popup = tk.Toplevel(self.master)
        popup.title("Help")
        popup.transient(self.master) # Make it appear on top of the main window
        popup.grab_set() # Disable interaction with the main window

        # Calculate position to center it relative to the main window
        main_x = self.master.winfo_x()
        main_y = self.master.winfo_y()
        main_width = self.master.winfo_width()
        main_height = self.master.winfo_height()

        popup_width = 500
        popup_height = 300
        popup_x = main_x + (main_width // 2) - (popup_width // 2)
        popup_y = main_y + (main_height // 2) - (popup_height // 2)
        popup.geometry(f"{popup_width}x{popup_height}+{popup_x}+{popup_y}")
        popup.resizable(False, False)

        text_widget = scrolledtext.ScrolledText(popup, wrap=tk.WORD, font=("Consolas", 10), width=60, height=15)
        text_widget.pack(expand=True, fill="both", padx=10, pady=10)
        text_widget.insert(tk.END, help_text)
        text_widget.config(state=tk.DISABLED)

        close_button = ttk.Button(popup, text="Close", command=popup.destroy)
        close_button.pack(pady=5)

    def _create_target_tab(self, parent_frame):
        parent_frame.grid_columnconfigure(1, weight=1) # Make the second column (entry fields) expandable
        row = 0
        self._create_input_field(parent_frame, "Target URL (--url):", row, "url_entry", width=60,
                                 help_text="The URL of the WordPress installation to scan. Example: https://example.com")
        row += 1
        self._create_input_field(parent_frame, "Proxy (--proxy):", row, "proxy_entry", width=60,
                                 help_text="Proxy to use for requests. Format: protocol://host:port. Example: http://127.0.0.1:8080")
        row += 1
        self._create_input_field(parent_frame, "Headers (--headers):", row, "headers_entry", width=60,
                                 help_text="Custom HTTP headers. Format: 'Header-Name: Value'. Use one per line.")
        row += 1
        self._create_input_field(parent_frame, "User-Agent (--user-agent):", row, "user_agent_entry", width=60,
                                 help_text="Custom User-Agent header.")
        row += 1
        self.random_agent_var = tk.BooleanVar()
        self._create_input_field(parent_frame, "Random User-Agent (--random-user-agent):", row, None, is_checkbox=True, var_name="random_agent_var",
                                 help_text="Use a random User-Agent for each request.")
        row += 1
        self._create_input_field(parent_frame, "Cookie (--cookie):", row, "cookie_entry", width=60,
                                 help_text="Custom HTTP cookies. Format: 'name=value; name2=value2'.")
        row += 1
        self._create_input_field(parent_frame, "Basic Auth (--http-auth):", row, "http_auth_entry", width=60,
                                 help_text="HTTP Basic Authentication. Format: 'username:password'.")
        row += 1
        self.force_var = tk.BooleanVar()
        self._create_input_field(parent_frame, "Force Scan (--force):", row, None, is_checkbox=True, var_name="force_var",
                                 help_text="Force WPScan to scan, even if it detects it's not a WordPress site.")
        row += 1
        self.follow_redirects_var = tk.BooleanVar()
        self._create_input_field(parent_frame, "Follow Redirects (--follow-redirects):", row, None, is_checkbox=True, var_name="follow_redirects_var",
                                 help_text="Follow HTTP redirects.")
        row += 1
        self.no_tls_checks_var = tk.BooleanVar()
        self._create_input_field(parent_frame, "No TLS Checks (--no-tls-checks):", row, None, is_checkbox=True, var_name="no_tls_checks_var",
                                 help_text="Do not perform TLS certificate validation.")

    def _create_enumeration_tab(self, parent_frame):
        parent_frame.grid_columnconfigure(0, weight=1) # Allow the frames to expand
        parent_frame.grid_columnconfigure(1, weight=1)
        row = 0

        enum_options = [
            ("vp", "Vulnerable Plugins"),
            ("vt", "Vulnerable Themes"),
            ("u", "Users (from permalink guessing)"),
            ("u1-10", "Users (from ID range 1-10)"),
            ("ap", "All Plugins"),
            ("at", "All Themes"),
            ("d", "Debug Log Files"),
            ("t", "Timthumbs"),
            ("r", "Revolution Slider files"),
            ("m", "Media Replacer files"),
            ("e", "All (equivalent to vp,vt,u,ap,at,d,t,r,m)"),
        ]

        ttk.Label(parent_frame, text="Enumeration Options (--enumerate):", font=("Arial", 10, "bold")).grid(row=row, column=0, columnspan=3, sticky="w", pady=(10,0))
        row += 1

        self.enumerate_vars = {}
        for i, (value, text) in enumerate(enum_options):
            var_name = f"enum_{value.replace('-', '_')}_var"
            self.enumerate_vars[value] = tk.BooleanVar()
            self._create_input_field(parent_frame, text, row + i // 2, None, col=(i % 2) * 2, is_checkbox=True, var_name=var_name,
                                     help_text=f"Enumerate {text.lower()}.")
            setattr(self, var_name, self.enumerate_vars[value]) # Set the actual attribute

        row += (len(enum_options) + 1) // 2 # Adjust row for next section

        self._create_input_field(parent_frame, "Plugins to enumerate (--plugins-detection):", row, "plugins_detection_entry", width=60,
                                 help_text="Comma-separated list of plugins to detect. Example: 'contact-form-7,yoast-seo'")
        row += 1
        self._create_input_field(parent_frame, "Themes to enumerate (--themes-detection):", row, "themes_detection_entry", width=60,
                                 help_text="Comma-separated list of themes to detect. Example: 'twentytwentyone,astra'")
        row += 1
        self._create_input_field(parent_frame, "Exclude Plugins (--exclude-content-plugins):", row, "exclude_plugins_entry", width=60,
                                 help_text="Comma-separated list of plugins to exclude from enumeration.")
        row += 1
        self._create_input_field(parent_frame, "Exclude Themes (--exclude-content-themes):", row, "exclude_themes_entry", width=60,
                                 help_text="Comma-separated list of themes to exclude from enumeration.")
        row += 1
        self._create_input_field(parent_frame, "Exclude Users (--exclude-content-users):", row, "exclude_users_entry", width=60,
                                 help_text="Comma-separated list of users to exclude from enumeration.")

    def _create_bruteforce_tab(self, parent_frame):
        parent_frame.grid_columnconfigure(1, weight=1)
        row = 0
        self._create_input_field(parent_frame, "Usernames File (--usernames):", row, "usernames_file_entry", width=60,
                                 help_text="Path to a file containing usernames to brute-force.")
        row += 1
        self._create_input_field(parent_frame, "Passwords File (--passwords):", row, "passwords_file_entry", width=60,
                                 help_text="Path to a file containing passwords to brute-force.")
        row += 1
        self._create_input_field(parent_frame, "Username (--username):", row, "username_entry", width=40,
                                 help_text="Specific username to brute-force.")
        row += 1
        self._create_input_field(parent_frame, "Password (--password):", row, "password_entry", width=40,
                                 help_text="Specific password to brute-force (use with --username).")
        row += 1
        self._create_input_field(parent_frame, "Threads (--threads):", row, "threads_entry", width=10,
                                 help_text="Number of threads to use for brute-force attacks (default: 5).")
        row += 1
        self.max_threads_var = tk.BooleanVar()
        self._create_input_field(parent_frame, "Max Threads (--max-threads):", row, None, is_checkbox=True, var_name="max_threads_var",
                                 help_text="Use the maximum number of threads possible.")
        row += 1
        self._create_input_field(parent_frame, "Attack Interval (--attack-interval):", row, "attack_interval_entry", width=10,
                                 help_text="Delay in seconds between each brute-force attempt.")

    def _create_update_api_tab(self, parent_frame):
        parent_frame.grid_columnconfigure(1, weight=1)
        row = 0
        self.update_var = tk.BooleanVar()
        self._create_input_field(parent_frame, "Update Database (--update):", row, None, is_checkbox=True, var_name="update_var",
                                 help_text="Update the WPScan database.")
        row += 1
        self._create_input_field(parent_frame, "API Token (--api-token):", row, "api_token_entry", width=60,
                                 help_text="WPScan API token for enhanced vulnerability detection.")
        row += 1
        self.clear_cache_var = tk.BooleanVar()
        self._create_input_field(parent_frame, "Clear Cache (--clear-cache):", row, None, is_checkbox=True, var_name="clear_cache_var",
                                 help_text="Clear the WPScan cache.")

    def _create_advanced_tab(self, parent_frame):
        parent_frame.grid_columnconfigure(1, weight=1)
        row = 0
        self._create_input_field(parent_frame, "Output Format (--format):", row, "format_entry", width=20, is_dropdown=True, var_name="format_var",
                                 options=["", "cli", "json", "xml"],
                                 help_text="Output format (cli, json, xml). Default is cli.")
        row += 1
        self._create_input_field(parent_frame, "Output File (--output):", row, "output_file_entry", width=60,
                                 help_text="Save output to a file.")
        row += 1
        self._create_input_field(parent_frame, "Verbosity (--verbose):", row, "verbose_entry", width=10,
                                 help_text="Increase verbosity level. Use multiple times for more verbose output.")
        row += 1
        self.debug_var = tk.BooleanVar()
        self._create_input_field(parent_frame, "Debug (--debug):", row, None, is_checkbox=True, var_name="debug_var",
                                 help_text="Output debug information.")
        row += 1
        self.no_color_var = tk.BooleanVar()
        self._create_input_field(parent_frame, "No Color (--no-color):", row, None, is_checkbox=True, var_name="no_color_var",
                                 help_text="Disable colored output.")
        row += 1
        self.random_agent_var = tk.BooleanVar() # This is already defined in Target tab, re-using for consistency
        self._create_input_field(parent_frame, "Random User-Agent (--random-user-agent):", row, None, is_checkbox=True, var_name="random_agent_var",
                                 help_text="Use a random User-Agent for each request.")
        row += 1
        self.detection_mode_var = tk.StringVar()
        self._create_input_field(parent_frame, "Detection Mode (--detection-mode):", row, "detection_mode_entry", width=20, is_dropdown=True, var_name="detection_mode_var",
                                 options=["", "mixed", "passive", "aggressive"],
                                 help_text="Set detection mode (mixed, passive, aggressive).")
        row += 1
        self._create_input_field(parent_frame, "Additional Arguments:", row, "additional_args_entry", width=60,
                                 help_text="Any other WPScan arguments not covered by the GUI. E.g., --disable-tls")

    def generate_command(self):
        command_parts = ["wpscan"]

        # Helper to add arguments if value is not empty
        def add_arg(arg_name, entry_widget, is_text_area=False):
            if is_text_area:
                value = entry_widget.get("1.0", tk.END).strip()
            else:
                value = entry_widget.get().strip()
            if value:
                command_parts.append(arg_name)
                command_parts.append(shlex.quote(value)) # Quote values to handle spaces

        # Helper to add checkbox arguments
        def add_checkbox_arg(arg_name, var_widget):
            if var_widget.get():
                command_parts.append(arg_name)

        # Helper to add dropdown arguments
        def add_dropdown_arg(arg_name, var_widget):
            value = var_widget.get().strip()
            if value:
                command_parts.append(arg_name)
                command_parts.append(value)

        # Target Options
        add_arg("--url", self.url_entry)
        add_arg("--proxy", self.proxy_entry)
        
        headers = self.headers_entry.get("1.0", tk.END).strip()
        if headers:
            for header_line in headers.split('\n'):
                header_line = header_line.strip()
                if header_line:
                    command_parts.append("--headers")
                    command_parts.append(shlex.quote(header_line))
        
        add_arg("--user-agent", self.user_agent_entry)
        add_checkbox_arg("--random-user-agent", self.random_agent_var)
        add_arg("--cookie", self.cookie_entry)
        add_arg("--http-auth", self.http_auth_entry)
        add_checkbox_arg("--force", self.force_var)
        add_checkbox_arg("--follow-redirects", self.follow_redirects_var)
        add_checkbox_arg("--no-tls-checks", self.no_tls_checks_var)

        # Enumeration Options
        enum_values = []
        for value, _ in self.enumerate_vars.items():
            if self.enumerate_vars[value].get():
                enum_values.append(value)
        if enum_values:
            command_parts.append("--enumerate")
            command_parts.append(",".join(enum_values))

        add_arg("--plugins-detection", self.plugins_detection_entry)
        add_arg("--themes-detection", self.themes_detection_entry)
        add_arg("--exclude-content-plugins", self.exclude_plugins_entry)
        add_arg("--exclude-content-themes", self.exclude_themes_entry)
        add_arg("--exclude-content-users", self.exclude_users_entry)

        # Brute-Force Tab
        add_arg("--usernames", self.usernames_file_entry)
        add_arg("--passwords", self.passwords_file_entry)
        add_arg("--username", self.username_entry)
        add_arg("--password", self.password_entry)
        add_arg("--threads", self.threads_entry)
        add_checkbox_arg("--max-threads", self.max_threads_var)
        add_arg("--attack-interval", self.attack_interval_entry)

        # Update & API Tab
        add_checkbox_arg("--update", self.update_var)
        add_arg("--api-token", self.api_token_entry)
        add_checkbox_arg("--clear-cache", self.clear_cache_var)

        # Advanced Tab
        add_dropdown_arg("--format", self.format_var)
        add_arg("--output", self.output_file_entry)
        add_arg("--verbose", self.verbose_entry) # WPScan uses --verbose, not -v multiple times
        add_checkbox_arg("--debug", self.debug_var)
        add_checkbox_arg("--no-color", self.no_color_var)
        add_dropdown_arg("--detection-mode", self.detection_mode_var)
        
        # Additional Arguments
        additional_args = self.additional_args_entry.get("1.0", tk.END).strip()
        if additional_args:
            try:
                split_args = shlex.split(additional_args)
                command_parts.extend(split_args)
            except ValueError:
                messagebox.showwarning("Command Generation Error", "Could not parse additional arguments. Please check quotes.")
                command_parts.append(additional_args) # Fallback

        generated_cmd = " ".join(command_parts)
        self.command_text.config(state=tk.NORMAL)
        self.command_text.delete(1.0, tk.END)
        self.command_text.insert(tk.END, generated_cmd)
        self.command_text.config(state=tk.DISABLED)

    def copy_command(self):
        command_to_copy = self.command_text.get("1.0", tk.END).strip()
        self.master.clipboard_clear()
        self.master.clipboard_append(command_to_copy)
        messagebox.showinfo("Copy Command", "Command copied to clipboard!")

    def run_wpscan(self):
        if self.wpscan_process and self.wpscan_process.poll() is None:
            messagebox.showwarning("WPScan Running", "WPScan is already running. Please wait for it to finish or close the application.")
            return

        self.clear_output()
        self.status_bar.config(text="WPScan is running...")
        self.output_text.config(state=tk.NORMAL)
        self.output_text.insert(tk.END, "Starting WPScan...\n")
        self.output_text.config(state=tk.DISABLED)

        # Generate the command just before running to ensure it's up-to-date
        self.generate_command()
        command_str = self.command_text.get("1.0", tk.END).strip()
        
        # Use shlex.split to correctly handle quoted arguments for subprocess
        try:
            command = shlex.split(command_str)
        except ValueError as e:
            self.output_text.config(state=tk.NORMAL)
            self.output_text.insert(tk.END, f"Error parsing command: {e}\n")
            self.output_text.config(state=tk.DISABLED)
            self.status_bar.config(text="Error")
            return

        self.output_text.config(state=tk.NORMAL)
        self.output_text.insert(tk.END, f"Executing command: {command_str}\n\n")
        self.output_text.config(state=tk.DISABLED)

        # Run wpscan in a separate thread
        self.wpscan_thread = threading.Thread(target=self._run_wpscan_thread, args=(command,))
        self.wpscan_thread.daemon = True
        self.wpscan_thread.start()

    def _run_wpscan_thread(self, command):
        try:
            # Check if wpscan is available in PATH
            import shutil
            if shutil.which(command[0]) is None:
                self.output_queue.put(f"Error: '{command[0]}' not found in system PATH. Please ensure wpscan is installed and accessible.\n")
                self.output_queue.put("STATUS: Error\n")
                return

            self.wpscan_process = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1, # Line-buffered
                universal_newlines=True
            )

            # Use a separate thread for reading stdout/stderr to avoid blocking
            def read_output(pipe, output_queue):
                for line in iter(pipe.readline, ''):
                    output_queue.put(line)
                pipe.close()

            stdout_thread = threading.Thread(target=read_output, args=(self.wpscan_process.stdout, self.output_queue))
            stderr_thread = threading.Thread(target=read_output, args=(self.wpscan_process.stderr, self.output_queue))
            stdout_thread.daemon = True
            stderr_thread.daemon = True
            stdout_thread.start()
            stderr_thread.start()

            # Wait for wpscan process to finish
            self.wpscan_process.wait()
            return_code = self.wpscan_process.returncode
            self.output_queue.put(f"\nWPScan finished with exit code: {return_code}\n")
            self.output_queue.put(f"STATUS: {'Completed' if return_code == 0 else 'Failed'}\n")

        except FileNotFoundError:
            self.output_queue.put("Error: wpscan command not found. Make sure wpscan is installed and in your system's PATH.\n")
            self.output_queue.put("STATUS: Error\n")
        except Exception as e:
            self.output_queue.put(f"An error occurred: {e}\n")
            self.output_queue.put("STATUS: Error\n")
        finally:
            self.master.after(0, lambda: setattr(self, 'wpscan_process', None)) # Clear process on main thread
            self.master.after(0, lambda: self.status_bar.config(text="Ready")) # Update status bar on main thread

    def process_queue(self):
        while not self.output_queue.empty():
            try:
                line = self.output_queue.get_nowait()
                self.output_text.config(state=tk.NORMAL)
                self.output_text.insert(tk.END, line)
                self.output_text.see(tk.END) # Scroll to the end
                self.output_text.config(state=tk.DISABLED)
            except queue.Empty:
                pass
        
        if self.wpscan_process and self.wpscan_process.poll() is None:
            self.status_bar.config(text="WPScan is running...")
        else:
            self.status_bar.config(text="Ready")

        self.master.after(100, self.process_queue)

    def clear_output(self):
        self.output_text.config(state=tk.NORMAL)
        self.output_text.delete(1.0, tk.END)
        self.output_text.config(state=tk.DISABLED)
        self.status_bar.config(text="Ready")
        self.clear_search_highlight() # Clear highlights when output is cleared

    def save_output(self):
        output_content = self.output_text.get("1.0", tk.END)
        if not output_content.strip():
            messagebox.showinfo("Save Output", "No output to save.")
            return

        file_path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
        )
        if file_path:
            try:
                with open(file_path, "w") as f:
                    f.write(output_content)
                messagebox.showinfo("Save Output", f"Output saved to {file_path}")
            except Exception as e:
                messagebox.showerror("Save Error", f"Failed to save file: {e}")

    def search_output(self, event=None):
        search_term = self.search_entry.get().strip()
        self.clear_search_highlight() # Clear previous highlights

        if not search_term:
            self.search_start_index = "1.0" # Reset search start
            return

        self.output_text.config(state=tk.NORMAL)
        
        # Start search from the beginning if it's a new search or no more matches from current position
        if self.search_start_index == "1.0" or not self.output_text.search(search_term, self.search_start_index, tk.END, nocase=1):
            self.search_start_index = "1.0"

        idx = self.output_text.search(search_term, self.search_start_index, tk.END, nocase=1)
        if idx:
            end_idx = f"{idx}+{len(search_term)}c"
            self.output_text.tag_add("highlight", idx, end_idx)
            self.output_text.see(idx) # Scroll to the found text
            self.search_start_index = end_idx # Set start for next search
        else:
            messagebox.showinfo("Search", f"No more occurrences of '{search_term}' found.")
            self.search_start_index = "1.0" # Reset for next search attempt

        self.output_text.config(state=tk.DISABLED)

    def clear_search_highlight(self):
        self.output_text.config(state=tk.NORMAL)
        self.output_text.tag_remove("highlight", "1.0", tk.END)
        self.output_text.config(state=tk.DISABLED)
        self.search_start_index = "1.0" # Reset search start index

    def on_closing(self):
        if self.wpscan_process and self.wpscan_process.poll() is None:
            if messagebox.askokcancel("Quit", "WPScan is still running. Do you want to terminate it and quit?"):
                self.wpscan_process.terminate()
                self.master.destroy()
        else:
            self.master.destroy()

if __name__ == "__main__":
    root = tk.Tk()
    app = WpscanGUI(root)
    root.mainloop()
