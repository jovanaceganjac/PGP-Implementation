import datetime
import os
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, simpledialog

from pgp.keyring_store import KeyringError


class KeysTab(ttk.Frame):
    def __init__(self, parent, keyring_manager, on_keys_changed=None):
        super().__init__(parent, padding=10)
        self.km = keyring_manager
        self.on_keys_changed = on_keys_changed
        self._build_ui()
        self.refresh()

    def _build_ui(self):
        gen_frame = ttk.LabelFrame(self, text="Generisanje novog para RSA kljuceva", padding=10)
        gen_frame.pack(fill="x", pady=(0, 10))

        ttk.Label(gen_frame, text="Ime i prezime:").grid(row=0, column=0, sticky="w", padx=5, pady=3)
        self.name_var = tk.StringVar()
        ttk.Entry(gen_frame, textvariable=self.name_var, width=25).grid(row=0, column=1, padx=5, pady=3)

        ttk.Label(gen_frame, text="Email:").grid(row=0, column=2, sticky="w", padx=5, pady=3)
        self.email_var = tk.StringVar()
        ttk.Entry(gen_frame, textvariable=self.email_var, width=25).grid(row=0, column=3, padx=5, pady=3)

        ttk.Label(gen_frame, text="Velicina kljuca:").grid(row=1, column=0, sticky="w", padx=5, pady=3)
        self.key_size_var = tk.IntVar(value=1024)
        size_frame = ttk.Frame(gen_frame)
        size_frame.grid(row=1, column=1, sticky="w", padx=5, pady=3)
        ttk.Radiobutton(size_frame, text="1024", variable=self.key_size_var, value=1024).pack(side="left")
        ttk.Radiobutton(size_frame, text="2048", variable=self.key_size_var, value=2048).pack(side="left")

        ttk.Label(gen_frame, text="Lozinka:").grid(row=2, column=0, sticky="w", padx=5, pady=3)
        self.pass_var = tk.StringVar()
        ttk.Entry(gen_frame, textvariable=self.pass_var, show="*", width=25).grid(row=2, column=1, padx=5, pady=3)

        ttk.Label(gen_frame, text="Potvrda lozinke:").grid(row=2, column=2, sticky="w", padx=5, pady=3)
        self.pass_confirm_var = tk.StringVar()
        ttk.Entry(gen_frame, textvariable=self.pass_confirm_var, show="*", width=25).grid(row=2, column=3, padx=5, pady=3)

        ttk.Button(gen_frame, text="Generisi par kljuceva", command=self._generate).grid(
            row=3, column=0, columnspan=4, pady=(8, 0)
        )

        lists_frame = ttk.Frame(self)
        lists_frame.pack(fill="both", expand=True, pady=(0, 10))

        priv_frame = ttk.LabelFrame(lists_frame, text="Prsten privatnih kljuceva", padding=5)
        priv_frame.pack(side="left", fill="both", expand=True, padx=(0, 5))
        self.priv_tree = ttk.Treeview(
            priv_frame, columns=("timestamp", "key_id", "user_id", "size"), show="headings", height=8
        )
        for col, text, width in [
            ("timestamp", "Vreme", 130), ("key_id", "Key ID", 130),
            ("user_id", "User ID", 220), ("size", "Velicina", 60),
        ]:
            self.priv_tree.heading(col, text=text)
            self.priv_tree.column(col, width=width)
        self.priv_tree.pack(fill="both", expand=True)
        self.priv_tree.bind("<<TreeviewSelect>>", lambda e: self.pub_tree.selection_remove(self.pub_tree.selection()))

        priv_btn_frame = ttk.Frame(priv_frame)
        priv_btn_frame.pack(fill="x", pady=(5, 0))
        ttk.Button(priv_btn_frame, text="Uvezi par kljuceva...", command=self._import_pair).pack(side="left", padx=3)
        ttk.Button(priv_btn_frame, text="Izvezi par kljuceva...", command=self._export_pair).pack(side="left", padx=3)

        pub_frame = ttk.LabelFrame(lists_frame, text="Prsten javnih kljuceva", padding=5)
        pub_frame.pack(side="left", fill="both", expand=True, padx=(5, 0))
        self.pub_tree = ttk.Treeview(
            pub_frame, columns=("timestamp", "key_id", "user_id", "size"), show="headings", height=8
        )
        for col, text, width in [
            ("timestamp", "Vreme", 130), ("key_id", "Key ID", 130),
            ("user_id", "User ID", 220), ("size", "Velicina", 60),
        ]:
            self.pub_tree.heading(col, text=text)
            self.pub_tree.column(col, width=width)
        self.pub_tree.pack(fill="both", expand=True)
        self.pub_tree.bind("<<TreeviewSelect>>", lambda e: self.priv_tree.selection_remove(self.priv_tree.selection()))

        pub_btn_frame = ttk.Frame(pub_frame)
        pub_btn_frame.pack(fill="x", pady=(5, 0))
        ttk.Button(pub_btn_frame, text="Uvezi javni kljuc...", command=self._import_public).pack(side="left", padx=3)
        ttk.Button(pub_btn_frame, text="Izvezi javni kljuc...", command=self._export_public).pack(side="left", padx=3)

        btn_frame = ttk.Frame(self)
        btn_frame.pack(fill="x")
        ttk.Button(btn_frame, text="Obrisi selektovano", command=self._delete_selected).pack(side="left", padx=3)


    def refresh(self):
        self.priv_tree.delete(*self.priv_tree.get_children())
        for e in self.km.private_entries:
            self.priv_tree.insert("", "end", iid=e.key_id, values=(
                self._fmt_time(e.timestamp), e.key_id, e.user_id, e.key_size
            ))

        self.pub_tree.delete(*self.pub_tree.get_children())
        for e in self.km.public_entries:
            self.pub_tree.insert("", "end", iid=e.key_id, values=(
                self._fmt_time(e.timestamp), e.key_id, e.user_id, e.public_key().key_size
            ))

        if self.on_keys_changed:
            self.on_keys_changed()

    @staticmethod
    def _fmt_time(ts: int) -> str:
        return datetime.datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M")

    def _selected_key_id(self, tree):
        sel = tree.selection()
        return sel[0] if sel else None

    def _generate(self):
        name = self.name_var.get().strip()
        email = self.email_var.get().strip()
        passphrase = self.pass_var.get()
        confirm = self.pass_confirm_var.get()

        if not name or not email:
            messagebox.showerror("Greska", "Unesite ime i email.")
            return
        if not passphrase:
            messagebox.showerror("Greska", "Unesite lozinku za zastitu privatnog kljuca.")
            return
        if passphrase != confirm:
            messagebox.showerror("Greska", "Lozinka i potvrda lozinke se ne poklapaju.")
            return

        try:
            entry = self.km.generate_keypair(name, email, self.key_size_var.get(), passphrase)
        except Exception as e:
            messagebox.showerror("Greska pri generisanju kljuceva", str(e))
            return

        self.pass_var.set("")
        self.pass_confirm_var.set("")
        messagebox.showinfo("Uspeh", f"Generisan je novi par kljuceva.\nKey ID: {entry.key_id}")
        self.refresh()

    def _delete_selected(self):
        priv_id = self._selected_key_id(self.priv_tree)
        pub_id = self._selected_key_id(self.pub_tree)

        if not priv_id and not pub_id:
            messagebox.showwarning("Napomena", "Selektujte kljuc koji zelite da obrisete.")
            return

        if not messagebox.askyesno("Potvrda", "Da li ste sigurni da zelite da obrisete selektovani kljuc?"):
            return

        if priv_id:
            self.km.delete_private(priv_id)
        if pub_id:
            self.km.delete_public(pub_id)
        self.refresh()

    def _import_public(self):
        path = filedialog.askopenfilename(title="Uvezi javni kljuc", filetypes=[("PEM fajlovi", "*.pem"), ("Svi fajlovi", "*.*")])
        if not path:
            return
        try:
            entry = self.km.import_public_key_file(path)
        except KeyringError as e:
            if "User-ID" in str(e):
                user_id = self._ask_user_id()
                if not user_id:
                    return
                try:
                    entry = self.km.import_public_key_file(path, user_id=user_id)
                except KeyringError as e2:
                    messagebox.showerror("Greska pri uvozu", str(e2))
                    return
            else:
                messagebox.showerror("Greska pri uvozu", str(e))
                return
        except Exception as e:
            messagebox.showerror("Greska pri uvozu", str(e))
            return

        messagebox.showinfo("Uspeh", f"Uvezen je javni kljuc.\nKey ID: {entry.key_id}\nUser ID: {entry.user_id}")
        self.refresh()

    def _import_pair(self):
        path = filedialog.askopenfilename(title="Uvezi par kljuceva", filetypes=[("PEM fajlovi", "*.pem"), ("Svi fajlovi", "*.*")])
        if not path:
            return
        pem_pass = simpledialog.askstring("Lozinka fajla", "Unesite lozinku kojom je zasticen ovaj fajl:", show="*", parent=self)
        if pem_pass is None:
            return
        keyring_pass = simpledialog.askstring(
            "Lozinka prstena", "Unesite lozinku za cuvanje ovog privatnog kljuca u lokalnom prstenu:", show="*", parent=self
        )
        if keyring_pass is None:
            return

        try:
            entry = self.km.import_keypair_file(path, pem_pass, keyring_pass)
        except KeyringError as e:
            if "User-ID" in str(e):
                user_id = self._ask_user_id()
                if not user_id:
                    return
                try:
                    entry = self.km.import_keypair_file(path, pem_pass, keyring_pass, user_id=user_id)
                except KeyringError as e2:
                    messagebox.showerror("Greska pri uvozu", str(e2))
                    return
            else:
                messagebox.showerror("Greska pri uvozu", str(e))
                return
        except Exception as e:
            messagebox.showerror("Greska pri uvozu", str(e))
            return

        messagebox.showinfo("Uspeh", f"Uvezen je par kljuceva.\nKey ID: {entry.key_id}\nUser ID: {entry.user_id}")
        self.refresh()

    def _ask_user_id(self):
        name = simpledialog.askstring("User ID", "Fajl ne sadrzi User-ID. Unesite ime i prezime:", parent=self)
        if not name:
            return None
        email = simpledialog.askstring("User ID", "Unesite email:", parent=self)
        if not email:
            return None
        return f"{name} <{email}>"

    @staticmethod
    def _force_pem_extension(path: str) -> str:
        # macOS dijalog za cuvanje ume da promeni .pem u .cer, pa ovde vracamo .pem
        root, ext = os.path.splitext(path)
        if ext.lower() != ".pem":
            return root + ".pem"
        return path

    def _export_public(self):
        priv_id = self._selected_key_id(self.priv_tree)
        pub_id = self._selected_key_id(self.pub_tree)
        key_id = priv_id or pub_id
        if not key_id:
            messagebox.showwarning("Napomena", "Selektujte kljuc koji zelite da izvezete.")
            return

        path = filedialog.asksaveasfilename(title="Izvezi javni kljuc", defaultextension=".pem",
                                             filetypes=[("PEM fajlovi", "*.pem")])
        if not path:
            return
        path = self._force_pem_extension(path)
        try:
            self.km.export_public_key(key_id, path)
        except Exception as e:
            messagebox.showerror("Greska pri izvozu", str(e))
            return
        messagebox.showinfo("Uspeh", "Javni kljuc je izvezen.")

    def _export_pair(self):
        priv_id = self._selected_key_id(self.priv_tree)
        if not priv_id:
            messagebox.showwarning("Napomena", "Selektujte par kljuceva (iz prstena privatnih kljuceva) za izvoz.")
            return

        unlock_pass = simpledialog.askstring("Lozinka", "Unesite lozinku kojom je zasticen ovaj privatni kljuc:", show="*", parent=self)
        if unlock_pass is None:
            return
        export_pass = simpledialog.askstring("Lozinka izvoza", "Unesite lozinku kojom ce biti zasticen izvezeni fajl:", show="*", parent=self)
        if export_pass is None:
            return

        path = filedialog.asksaveasfilename(title="Izvezi par kljuceva", defaultextension=".pem",
                                             filetypes=[("PEM fajlovi", "*.pem")])
        if not path:
            return
        path = self._force_pem_extension(path)

        try:
            self.km.export_keypair(priv_id, path, unlock_pass, export_pass)
        except Exception as e:
            messagebox.showerror("Greska pri izvozu", str(e))
            return
        messagebox.showinfo("Uspeh", "Par kljuceva je izvezen.")
