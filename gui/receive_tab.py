import tkinter as tk
from tkinter import ttk, filedialog, messagebox, simpledialog

from pgp import message


class ReceiveTab(ttk.Frame):
    def __init__(self, parent, keyring_manager):
        super().__init__(parent, padding=10)
        self.km = keyring_manager
        self.last_result = None
        self._build_ui()

    def _build_ui(self):
        ttk.Button(self, text="Otvori fajl poruke...", command=self._open).pack(anchor="w")

        info_frame = ttk.LabelFrame(self, text="Informacije o poruci", padding=10)
        info_frame.pack(fill="x", pady=10)

        self.info_labels = {}
        rows = [
            ("filename", "Naziv fajla:"),
            ("encrypted", "Sifrovano:"),
            ("compressed", "Kompresija:"),
            ("signed", "Potpisano:"),
            ("signature_status", "Status potpisa:"),
            ("signer", "Autor potpisa:"),
        ]
        for i, (key, label) in enumerate(rows):
            ttk.Label(info_frame, text=label).grid(row=i, column=0, sticky="w", padx=5, pady=2)
            value_label = ttk.Label(info_frame, text="-", font=("TkDefaultFont", 10, "bold"))
            value_label.grid(row=i, column=1, sticky="w", padx=5, pady=2)
            self.info_labels[key] = value_label

        ttk.Label(self, text="Sadrzaj poruke:").pack(anchor="w")
        text_frame = ttk.Frame(self)
        text_frame.pack(fill="both", expand=True, pady=(0, 5))
        self.preview = tk.Text(text_frame, height=10, wrap="word", state="disabled")
        scroll = ttk.Scrollbar(text_frame, command=self.preview.yview)
        self.preview.configure(yscrollcommand=scroll.set)
        self.preview.pack(side="left", fill="both", expand=True)
        scroll.pack(side="left", fill="y")

        self.save_button = ttk.Button(self, text="Sacuvaj originalnu poruku kao...",
                                       command=self._save_original, state="disabled")
        self.save_button.pack(anchor="e")

    def refresh_keys(self):
        pass

    def _get_passphrase(self, private_entry):
        return simpledialog.askstring(
            "Lozinka", f"Unesite lozinku za privatni kljuc ({private_entry.user_id}):", show="*", parent=self
        )

    def _open(self):
        path = filedialog.askopenfilename(title="Otvori poruku")
        if not path:
            return
        try:
            with open(path, "rb") as f:
                raw_bytes = f.read()
        except Exception as e:
            messagebox.showerror("Greska", f"Ne mogu da ucitam fajl: {e}")
            return

        try:
            result = message.parse_message(
                raw_bytes,
                find_private_by_id=self.km.find_private,
                find_public_by_id=self.km.find_public,
                get_passphrase=self._get_passphrase,
            )
        except message.MessageError as e:
            self._reset_info()
            messagebox.showerror("Greska pri prijemu poruke", str(e))
            return
        except Exception as e:
            self._reset_info()
            messagebox.showerror("Greska pri prijemu poruke", f"Neocekivana greska: {e}")
            return

        self.last_result = result
        self._show_result(result)

    def _reset_info(self):
        self.last_result = None
        for label in self.info_labels.values():
            label.configure(text="-")
        self.preview.configure(state="normal")
        self.preview.delete("1.0", "end")
        self.preview.configure(state="disabled")
        self.save_button.configure(state="disabled")

    def _show_result(self, result: message.ReceiveResult):
        self.info_labels["filename"].configure(text=result.filename)
        self.info_labels["encrypted"].configure(text="Da" if result.encrypted else "Ne")
        self.info_labels["compressed"].configure(text="Da" if result.compressed else "Ne")
        self.info_labels["signed"].configure(text="Da" if result.signed else "Ne")

        if not result.signed:
            self.info_labels["signature_status"].configure(text="-")
            self.info_labels["signer"].configure(text="-")
        elif result.signer_user_id is None:
            self.info_labels["signature_status"].configure(text="Nepoznat potpisnik", foreground="orange")
            self.info_labels["signer"].configure(text=f"Nepoznat (Key ID: {result.signer_key_id})")
        elif result.signature_valid:
            self.info_labels["signature_status"].configure(text="Validan potpis", foreground="green")
            self.info_labels["signer"].configure(text=result.signer_user_id, foreground="black")
        else:
            self.info_labels["signature_status"].configure(text="NEVALIDAN POTPIS", foreground="red")
            self.info_labels["signer"].configure(text=result.signer_user_id, foreground="black")

        self.preview.configure(state="normal")
        self.preview.delete("1.0", "end")
        try:
            preview_text = result.data.decode("utf-8")
        except UnicodeDecodeError:
            preview_text = f"[Binarni sadrzaj, {len(result.data)} bajtova - koristite 'Sacuvaj kao' da ga preuzmete]"
        self.preview.insert("1.0", preview_text)
        self.preview.configure(state="disabled")

        self.save_button.configure(state="normal")

        if result.signed and result.signature_valid is False:
            messagebox.showwarning(
                "Upozorenje",
                "Poruka je primljena, ali potpis NIJE validan ili je posiljalac nepoznat!\n"
                "Sadrzaj poruke je mozda izmenjen ili potpisan od strane nepouzdanog posiljaoca."
            )

    def _save_original(self):
        if self.last_result is None:
            return
        dest = filedialog.asksaveasfilename(title="Sacuvaj originalnu poruku",
                                             initialfile=self.last_result.filename)
        if not dest:
            return
        try:
            with open(dest, "wb") as f:
                f.write(self.last_result.data)
        except Exception as e:
            messagebox.showerror("Greska", f"Ne mogu da sacuvam fajl: {e}")
            return
        messagebox.showinfo("Uspeh", f"Poruka je sacuvana:\n{dest}")
