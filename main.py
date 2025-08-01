import sqlite3
import random
import string
import tkinter as tk
from tkinter import ttk, messagebox
import ttkbootstrap as tb
from ttkbootstrap.constants import *
from datetime import datetime


#create DB
def init_db():
    conn = sqlite3.connect("passwords.db")
    cursor = conn.cursor()

    #base table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS passwords (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            site TEXT NOT NULL,
            username TEXT NOT NULL,
            password TEXT NOT NULL
        )
    """)

    # Ellenőrizzük, hogy létezik-e a created_date oszlop
    cursor.execute("PRAGMA table_info(passwords)")
    columns = [column[1] for column in cursor.fetchall()]

    # Új oszlopok hozzáadása, ha nem léteznek
    if 'created_date' not in columns:
        cursor.execute("ALTER TABLE passwords ADD COLUMN created_date TEXT DEFAULT ''")
        # Meglévő sorok frissítése alapértelmezett dátummal
        cursor.execute(
            "UPDATE passwords SET created_date = '2024-01-01 00:00' WHERE created_date = '' OR created_date IS NULL")

    if 'category' not in columns:
        cursor.execute("ALTER TABLE passwords ADD COLUMN category TEXT DEFAULT 'General'")
        # Meglévő sorok frissítése alapértelmezett kategóriával
        cursor.execute("UPDATE passwords SET category = 'General' WHERE category = '' OR category IS NULL")

    conn.commit()
    conn.close()


#create psw
def generate_password():
    length = int(length_var.get())

    chars = ""
    if use_lowercase.get():
        chars += string.ascii_lowercase
    if use_uppercase.get():
        chars += string.ascii_uppercase
    if use_digits.get():
        chars += string.digits
    if use_special.get():
        chars += "!@#$%^&*()_+-=[]{};:,.<>?"

    if not chars:
        show_custom_message("⚠️ Figyelem", "Válassz legalább egy karaktertípust!", "warning")
        return

    password = "".join(random.choice(chars) for _ in range(length))
    password_var.set(password)

    # Jelszó erősség értékelése
    strength = evaluate_password_strength(password)
    strength_label.config(text=f"Erősség: {strength}",
                          foreground=get_strength_color(strength))

    show_custom_message("✅ Siker", "Jelszó sikeresen generálva!", "success")


def evaluate_password_strength(password):
    score = 0
    if len(password) >= 8: score += 1
    if len(password) >= 12: score += 1
    if any(c.islower() for c in password): score += 1
    if any(c.isupper() for c in password): score += 1
    if any(c.isdigit() for c in password): score += 1
    if any(c in "!@#$%^&*()_+-=[]{};:,.<>?" for c in password): score += 1

    if score <= 2:
        return "Gyenge"
    elif score <= 4:
        return "Közepes"
    else:
        return "Erős"


def get_strength_color(strength):
    colors = {"Gyenge": "#e74c3c", "Közepes": "#f39c12", "Erős": "#27ae60"}
    return colors.get(strength, "#000000")


#custom win
def show_custom_message(title, message, msg_type="info"):
    msg_window = tb.Toplevel(root)
    msg_window.title(title)
    msg_window.geometry("350x150")
    msg_window.resizable(False, False)
    msg_window.grab_set()

    #middle
    msg_window.transient(root)
    x = root.winfo_x() + (root.winfo_width() // 2) - 175
    y = root.winfo_y() + (root.winfo_height() // 2) - 75
    msg_window.geometry(f"350x150+{x}+{y}")

    frame = ttk.Frame(msg_window, padding=20)
    frame.pack(fill=BOTH, expand=True)

    ttk.Label(frame, text=message, font=("Segoe UI", 11), wraplength=300).pack(pady=20)

    style_map = {"info": INFO, "success": SUCCESS, "warning": WARNING, "error": DANGER}
    ttk.Button(frame, text="OK", command=msg_window.destroy,
               bootstyle=style_map.get(msg_type, INFO)).pack()


#save to db
def save_password():
    site = site_var.get().strip()
    username = username_var.get().strip()
    password = password_var.get().strip()
    category = category_var.get().strip() or "General"

    if not site or not username or not password:
        show_custom_message("❌ Hiba", "Kérlek tölts ki minden kötelező mezőt!", "error")
        return

    conn = sqlite3.connect("passwords.db")
    cursor = conn.cursor()
    cursor.execute("INSERT INTO passwords (site, username, password, created_date, category) VALUES (?, ?, ?, ?, ?)",
                   (site, username, password, datetime.now().strftime("%Y-%m-%d %H:%M"), category))
    conn.commit()
    conn.close()

    show_custom_message("✅ Mentve", "Jelszó sikeresen elmentve az adatbázisba!", "success")
    clear_fields()
    load_passwords()


def clear_fields():
    site_var.set("")
    username_var.set("")
    password_var.set("")
    category_var.set("")
    strength_label.config(text="Erősség: -", foreground="#666666")


#load search psw
def load_passwords(search_term="", category_filter=""):
    for row in tree.get_children():
        tree.delete(row)

    conn = sqlite3.connect("passwords.db")
    cursor = conn.cursor()

    query = "SELECT id, site, username, password, created_date, category FROM passwords WHERE site LIKE ?"
    params = [f"%{search_term}%"]

    if category_filter and category_filter != "Összes":
        query += " AND category = ?"
        params.append(category_filter)

    query += " ORDER BY created_date DESC"

    cursor.execute(query, params)
    for row in cursor.fetchall():
        # Jelszó elrejtése csillagokkal
        hidden_password = "*" * min(len(row[3]), 12)
        display_row = (row[1], row[2], hidden_password, row[4], row[5])
        tree.insert("", "end", values=display_row, tags=(row[0],))

    conn.close()
    update_stats()


def update_stats():
    conn = sqlite3.connect("passwords.db")
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM passwords")
    count = cursor.fetchone()[0]
    conn.close()
    stats_label.config(text=f"Összes jelszó: {count}")


#search filter
def search():
    term = search_var.get()
    category = category_filter_var.get()
    load_passwords(term, category)


def on_search_change(*args):
    search()


#show psw
def toggle_password_visibility():
    selection = tree.selection()
    if not selection:
        show_custom_message("ℹ️ Info", "Válassz ki egy sort a jelszó megtekintéséhez!", "info")
        return

    item_id = tree.item(selection[0])['tags'][0]

    conn = sqlite3.connect("passwords.db")
    cursor = conn.cursor()
    cursor.execute("SELECT password FROM passwords WHERE id = ?", (item_id,))
    result = cursor.fetchone()
    conn.close()

    if result:
        show_custom_message("🔑 Jelszó", f"Jelszó: {result[0]}", "info")


#delete psw
def delete_password():
    selection = tree.selection()
    if not selection:
        show_custom_message("ℹ️ Info", "Válassz ki egy sort a törléshez!", "info")
        return

    # Megerősítés kérése
    confirm_window = tb.Toplevel(root)
    confirm_window.title("Megerősítés")
    confirm_window.geometry("300x180")
    confirm_window.resizable(False, False)
    confirm_window.grab_set()
    confirm_window.transient(root)

    frame = ttk.Frame(confirm_window, padding=20)
    frame.pack(fill=BOTH, expand=True)

    ttk.Label(frame, text="Biztosan törölni szeretnéd ezt a bejegyzést?",
              wraplength=250).pack(pady=10)

    button_frame = ttk.Frame(frame)
    button_frame.pack()

    def confirm_delete():
        item_id = tree.item(selection[0])['tags'][0]
        conn = sqlite3.connect("passwords.db")
        cursor = conn.cursor()
        cursor.execute("DELETE FROM passwords WHERE id = ?", (item_id,))
        conn.commit()
        conn.close()

        confirm_window.destroy()
        show_custom_message("✅ Törölve", "Bejegyzés sikeresen törölve!", "success")
        load_passwords()

    ttk.Button(button_frame, text="Igen", command=confirm_delete,
               bootstyle=DANGER).pack(side=LEFT, padx=5)
    ttk.Button(button_frame, text="Mégse", command=confirm_window.destroy,
               bootstyle=SECONDARY).pack(side=LEFT, padx=5)


#load cate
def load_categories():
    try:
        conn = sqlite3.connect("passwords.db")
        cursor = conn.cursor()
        cursor.execute(
            "SELECT DISTINCT category FROM passwords WHERE category IS NOT NULL AND category != '' ORDER BY category")
        categories = [row[0] for row in cursor.fetchall()]
        conn.close()

        # Előre definiált kategóriák
        predefined_categories = ["General", "Social Media", "Email", "Banking", "Work", "Gaming", "Shopping", "Other"]

        # Kombináljuk a meglévő és előre definiált kategóriákat
        all_categories = list(set(predefined_categories + categories))
        all_categories.sort()

        return ["Összes"] + all_categories
    except sqlite3.OperationalError:
        # Ha még mindig nincs category oszlop, alapértelmezett lista
        return ["Összes", "General", "Social Media", "Email", "Banking", "Work", "Gaming", "Shopping", "Other"]


#main win
init_db()

# Modern dark theme
root = tb.Window(themename="vapor")
root.title("🔐 Modern Jelszókezelő")
root.geometry("900x700")
root.minsize(800, 600)

#icons
root.configure(bg="#1a1a1a")

#header
header_frame = ttk.Frame(root, padding=15)
header_frame.pack(fill=X)

title_label = ttk.Label(header_frame, text="🔐 Modern Jelszókezelő",
                        font=("Segoe UI", 18, "bold"))
title_label.pack(side=LEFT)

stats_label = ttk.Label(header_frame, text="Összes jelszó: 0",
                        font=("Segoe UI", 10))
stats_label.pack(side=RIGHT)

#interface
notebook = ttk.Notebook(root, padding=10)
notebook.pack(fill=BOTH, expand=True, padx=10, pady=5)

# Tab 1: Új jelszó
tab_new = ttk.Frame(notebook, padding=20)
notebook.add(tab_new, text="➕ Új jelszó")

# Beviteli mezők modern elrendezéssel
input_frame = ttk.LabelFrame(tab_new, text="📝 Jelszó adatok", padding=15)
input_frame.pack(fill=X, pady=(0, 15))

#grid layout
for i in range(5):
    input_frame.columnconfigure(1, weight=1)

ttk.Label(input_frame, text="🌐 Oldal neve:", font=("Segoe UI", 10)).grid(row=0, column=0, padx=10, pady=8, sticky=W)
site_var = tk.StringVar()
site_entry = ttk.Entry(input_frame, textvariable=site_var, width=40, font=("Segoe UI", 10))
site_entry.grid(row=0, column=1, padx=10, pady=8, sticky=EW)

ttk.Label(input_frame, text="👤 Felhasználónév:", font=("Segoe UI", 10)).grid(row=1, column=0, padx=10, pady=8, sticky=W)
username_var = tk.StringVar()
username_entry = ttk.Entry(input_frame, textvariable=username_var, width=40, font=("Segoe UI", 10))
username_entry.grid(row=1, column=1, padx=10, pady=8, sticky=EW)

ttk.Label(input_frame, text="🔑 Jelszó:", font=("Segoe UI", 10)).grid(row=2, column=0, padx=10, pady=8, sticky=W)
password_var = tk.StringVar()
password_entry = ttk.Entry(input_frame, textvariable=password_var, width=40, font=("Segoe UI", 10))
password_entry.grid(row=2, column=1, padx=10, pady=8, sticky=EW)

#how strong
strength_label = ttk.Label(input_frame, text="Erősség: -", font=("Segoe UI", 9))
strength_label.grid(row=2, column=2, padx=10, pady=8)

ttk.Label(input_frame, text="📁 Kategória:", font=("Segoe UI", 10)).grid(row=3, column=0, padx=10, pady=8, sticky=W)
category_var = tk.StringVar(value="General")
category_combo = ttk.Combobox(input_frame, textvariable=category_var, width=37, font=("Segoe UI", 10), state="readonly")
category_combo['values'] = ("General", "Social Media", "Email", "Banking", "Work", "Gaming", "Shopping", "Other")
category_combo.grid(row=3, column=1, padx=10, pady=8, sticky=EW)

#gen
gen_frame = ttk.LabelFrame(tab_new, text="⚙️ Jelszó generátor", padding=15)
gen_frame.pack(fill=X, pady=(0, 15))

#options
opts_frame = ttk.Frame(gen_frame)
opts_frame.pack(fill=X, pady=(0, 10))

use_lowercase = tk.BooleanVar(value=True)
use_uppercase = tk.BooleanVar(value=True)
use_digits = tk.BooleanVar(value=True)
use_special = tk.BooleanVar(value=True)
length_var = tk.IntVar(value=16)

ttk.Checkbutton(opts_frame, text="🔤 Kisbetűk", variable=use_lowercase).grid(row=0, column=0, padx=10, pady=5, sticky=W)
ttk.Checkbutton(opts_frame, text="🔠 Nagybetűk", variable=use_uppercase).grid(row=0, column=1, padx=10, pady=5, sticky=W)
ttk.Checkbutton(opts_frame, text="🔢 Számok", variable=use_digits).grid(row=0, column=2, padx=10, pady=5, sticky=W)
ttk.Checkbutton(opts_frame, text="🎯 Speciális", variable=use_special).grid(row=0, column=3, padx=10, pady=5, sticky=W)

length_frame = ttk.Frame(gen_frame)
length_frame.pack(fill=X, pady=(0, 10))
ttk.Label(length_frame, text="📏 Hossz:", font=("Segoe UI", 10)).pack(side=LEFT, padx=(0, 10))
length_spinbox = ttk.Spinbox(length_frame, from_=6, to=32, textvariable=length_var, width=5, state="readonly")
length_spinbox.pack(side=LEFT, padx=(0, 10))
ttk.Label(length_frame, text="karakter", font=("Segoe UI", 9)).pack(side=LEFT)

#btns
button_frame = ttk.Frame(tab_new)
button_frame.pack(fill=X, pady=10)

ttk.Button(button_frame, text="🎲 Jelszó generálás", command=generate_password,
           bootstyle=SUCCESS, width=20).pack(side=LEFT, padx=(0, 10))
ttk.Button(button_frame, text="💾 Mentés", command=save_password,
           bootstyle=PRIMARY, width=15).pack(side=LEFT, padx=(0, 10))
ttk.Button(button_frame, text="🗑️ Mezők törlése", command=clear_fields,
           bootstyle=SECONDARY, width=15).pack(side=LEFT)

#handle psw
tab_manage = ttk.Frame(notebook, padding=20)
notebook.add(tab_manage, text="📋 Jelszavak kezelése")

#search filter
search_frame = ttk.LabelFrame(tab_manage, text="🔍 Keresés és szűrés", padding=10)
search_frame.pack(fill=X, pady=(0, 15))

search_var = tk.StringVar()
search_var.trace('w', on_search_change)
ttk.Label(search_frame, text="🔍 Keresés:").pack(side=LEFT, padx=(0, 5))
ttk.Entry(search_frame, textvariable=search_var, width=25).pack(side=LEFT, padx=(0, 15))

ttk.Label(search_frame, text="📁 Kategória:").pack(side=LEFT, padx=(0, 5))
category_filter_var = tk.StringVar(value="Összes")
category_combo = ttk.Combobox(search_frame, textvariable=category_filter_var, width=15, state="readonly")
category_combo['values'] = load_categories()
category_combo.pack(side=LEFT, padx=(0, 10))
category_combo.bind('<<ComboboxSelected>>', on_search_change)

#list btns
control_frame = ttk.Frame(tab_manage)
control_frame.pack(fill=X, pady=(0, 10))

ttk.Button(control_frame, text="👁️ Jelszó megtekintése", command=toggle_password_visibility,
           bootstyle=INFO, width=20).pack(side=LEFT, padx=(0, 10))
ttk.Button(control_frame, text="🗑️ Törlés", command=delete_password,
           bootstyle=DANGER, width=12).pack(side=LEFT, padx=(0, 10))
ttk.Button(control_frame, text="🔄 Frissítés", command=lambda: load_passwords(),
           bootstyle=SUCCESS, width=12).pack(side=LEFT)

#Treeview
list_frame = ttk.Frame(tab_manage)
list_frame.pack(fill=BOTH, expand=True)

columns = ("site", "username", "password", "date", "category")
tree = ttk.Treeview(list_frame, columns=columns, show="headings", height=15)

#cols
tree.heading("site", text="🌐 Oldal")
tree.heading("username", text="👤 Felhasználó")
tree.heading("password", text="🔑 Jelszó")
tree.heading("date", text="📅 Létrehozva")
tree.heading("category", text="📁 Kategória")

tree.column("site", width=150, minwidth=100)
tree.column("username", width=150, minwidth=100)
tree.column("password", width=120, minwidth=80)
tree.column("date", width=130, minwidth=100)
tree.column("category", width=100, minwidth=80)

#scroll
scrollbar = ttk.Scrollbar(list_frame, orient=VERTICAL, command=tree.yview)
tree.configure(yscrollcommand=scrollbar.set)

tree.pack(side=LEFT, fill=BOTH, expand=True)
scrollbar.pack(side=RIGHT, fill=Y)

load_passwords()


#close
def on_closing():
    root.quit()
    root.destroy()


root.protocol("WM_DELETE_WINDOW", on_closing)
root.mainloop()