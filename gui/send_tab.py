import tkinter as tk
from tkinter import ttk, filedialog, messagebox, simpledialog

from pgp import message, rsa_keys
from pgp.ciphers import SUPPORTED_CIPHERS


class SendTab(ttk.Frame):
    def __init__(self, parent, keyring_manager):
        super().__init__(parent, padding=10)
        self.km = keyring_manager
        self._build_ui()

    def _build_ui(self):
        ttk.Label(self, text="Tekst poruke:").pack(anchor="w")
        text_frame = ttk.Frame(self)
        text_frame.pack(fill="both", expand=True, pady=(0, 5))
        self.text = tk.Text(text_frame, height=10, wrap="word")
        scroll = ttk.Scrollbar(text_frame, command=self.text.yview)
        self.text.configure(yscrollcommand=scroll.set)
        self.text.pack(side="left", fill="both", expand=True)
        scroll.pack(side="left", fill="y")

        options_frame = ttk.LabelFrame(self, text="Opcije zastite poruke", padding=10)
        options_frame.pack(fill="x", pady=(0, 10))

        self.sign_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(options_frame, text="Potpisivanje (autenticnost)", variable=self.sign_var,
                        command=self._update_state).grid(row=0, column=0, sticky="w")
        self.sign_key_combo = ttk.Combobox(options_frame, state="disabled", width=45)
        self.sign_key_combo.grid(row=0, column=1, padx=10, sticky="w")

        self.encrypt_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(options_frame, text="Enkripcija (tajnost)", variable=self.encrypt_var,
                        command=self._update_state).grid(row=1, column=0, sticky="w")
        self.encrypt_key_combo = ttk.Combobox(options_frame, state="disabled", width=45)
        self.encrypt_key_combo.grid(row=1, column=1, padx=10, sticky="w")

        ttk.Label(options_frame, text="Simetricni algoritam:").grid(row=2, column=0, sticky="w", pady=(5, 0))
        self.cipher_combo = ttk.Combobox(options_frame, state="disabled", width=20, values=SUPPORTED_CIPHERS)
        self.cipher_combo.current(0)
        self.cipher_combo.grid(row=2, column=1, sticky="w", padx=10, pady=(5, 0))

        self.compress_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(options_frame, text="Kompresija (ZIP)", variable=self.compress_var).grid(
            row=3, column=0, sticky="w", pady=(5, 0)
        )
        self.armor_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(options_frame, text="Radix-64 konverzija (ASCII armor)", variable=self.armor_var).grid(
            row=4, column=0, sticky="w"
        )

        ttk.Button(self, text="Sacuvaj poruku kao...", command=self._send).pack(anchor="e")

    def refresh_keys(self):
        priv_values = [f"{e.user_id}  [{e.key_id}]" for e in self.km.private_entries]
        pub_values = [f"{e.user_id}  [{e.key_id}]" for e in self.km.public_entries]
        self.sign_key_combo["values"] = priv_values
        self.encrypt_key_combo["values"] = pub_values
        if not priv_values:
            self.sign_key_combo.set("")
        if not pub_values:
            self.encrypt_key_combo.set("")

    def _update_state(self):
        self.sign_key_combo.configure(state="readonly" if self.sign_var.get() else "disabled")
        self.encrypt_key_combo.configure(state="readonly" if self.encrypt_var.get() else "disabled")
        self.cipher_combo.configure(state="readonly" if self.encrypt_var.get() else "disabled")

    @staticmethod
    def _extract_key_id(display_value: str) -> str:
        return display_value.rsplit("[", 1)[1].rstrip("]")

    def _send(self):
        self.refresh_keys()

        data = self.text.get("1.0", "end-1c").encode("utf-8")
        filename = "poruka.txt"

        if not data:
            messagebox.showwarning("Napomena", "Poruka je prazna.")
            return

        sign_private_key = None
        sign_key_id = None
        if self.sign_var.get():
            selection = self.sign_key_combo.get()
            if not selection:
                messagebox.showwarning("Napomena", "Izaberite privatni kljuc za potpisivanje.")
                return
            sign_key_id = self._extract_key_id(selection)
            entry = self.km.find_private(sign_key_id)
            passphrase = simpledialog.askstring(
                "Lozinka", f"Unesite lozinku za privatni kljuc ({entry.user_id}):", show="*", parent=self
            )
            if passphrase is None:
                return
            try:
                sign_private_key = rsa_keys.unlock_private_key(entry, passphrase)
            except ValueError as e:
                messagebox.showerror("Greska", str(e))
                return

        encrypt_public_key = None
        encrypt_recipient_key_id = None
        cipher_name = None
        if self.encrypt_var.get():
            selection = self.encrypt_key_combo.get()
            if not selection:
                messagebox.showwarning("Napomena", "Izaberite javni kljuc primaoca.")
                return
            encrypt_recipient_key_id = self._extract_key_id(selection)
            entry = self.km.find_public(encrypt_recipient_key_id)
            encrypt_public_key = entry.public_key()
            cipher_name = self.cipher_combo.get()
            if not cipher_name:
                messagebox.showwarning("Napomena", "Izaberite simetricni algoritam.")
                return

        try:
            msg_bytes = message.build_message(
                data, filename,
                sign_private_key=sign_private_key, sign_key_id=sign_key_id,
                encrypt_public_key=encrypt_public_key, encrypt_recipient_key_id=encrypt_recipient_key_id,
                cipher_name=cipher_name,
                compress=self.compress_var.get(),
                armor=self.armor_var.get(),
            )
        except Exception as e:
            messagebox.showerror("Greska pri kreiranju poruke", str(e))
            return

        default_ext = ".asc" if self.armor_var.get() else ".pgp"
        dest = filedialog.asksaveasfilename(title="Sacuvaj poruku", defaultextension=default_ext)
        if not dest:
            return
        try:
            with open(dest, "wb") as f:
                f.write(msg_bytes)
        except Exception as e:
            messagebox.showerror("Greska", f"Ne mogu da sacuvam fajl: {e}")
            return

        messagebox.showinfo("Uspeh", f"Poruka je sacuvana:\n{dest}")
