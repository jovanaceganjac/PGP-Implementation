import tkinter as tk
from tkinter import ttk

from pgp.keyring_store import KeyringManager

from .keys_tab import KeysTab
from .receive_tab import ReceiveTab
from .send_tab import SendTab


class App:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("Zastita podataka - PGP sema za elektronsku postu")
        self.root.geometry("900x650")

        self.km = KeyringManager()

        notebook = ttk.Notebook(root)
        notebook.pack(fill="both", expand=True)

        self.send_tab = SendTab(notebook, self.km)
        self.receive_tab = ReceiveTab(notebook, self.km)
        self.keys_tab = KeysTab(notebook, self.km, on_keys_changed=self._on_keys_changed)

        notebook.add(self.keys_tab, text="Kljucevi")
        notebook.add(self.send_tab, text="Slanje poruke")
        notebook.add(self.receive_tab, text="Prijem poruke")

        self._on_keys_changed()

    def _on_keys_changed(self):
        self.send_tab.refresh_keys()
        self.receive_tab.refresh_keys()
