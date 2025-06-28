import tkinter as tk
from tkinter import messagebox, simpledialog
from cryptography.fernet import Fernet
import base64, hashlib, os, json, cv2

# Biometric matching using ORB keypoints
def match_images(img1_path, img2_path, threshold=50):
    img1 = cv2.imread(img1_path, 0)
    img2 = cv2.imread(img2_path, 0)
    if img1 is None or img2 is None:
        return False
    orb = cv2.ORB_create()
    kp1, des1 = orb.detectAndCompute(img1, None)
    kp2, des2 = orb.detectAndCompute(img2, None)
    if des1 is None or des2 is None:
        return False
    bf = cv2.BFMatcher(cv2.NORM_HAMMING, crossCheck=True)
    matches = bf.match(des1, des2)
    score = sum([m.distance for m in matches]) / len(matches)
    return score < threshold

VAULT_FILE = "vault.json.enc"
MASTER_FILE = "master.hash"

def generate_key(master_password):
    key = hashlib.sha256(master_password.encode()).digest()
    return base64.urlsafe_b64encode(key)

def encrypt_data(data, key):
    return Fernet(key).encrypt(data.encode())

def decrypt_data(token, key):
    return Fernet(key).decrypt(token).decode()

def save_encrypted_vault(data_dict, key):
    encrypted = encrypt_data(json.dumps(data_dict), key)
    with open(VAULT_FILE, "wb") as f:
        f.write(encrypted)

def load_encrypted_vault(key):
    if not os.path.exists(VAULT_FILE):
        return {}
    try:
        with open(VAULT_FILE, "rb") as f:
            encrypted = f.read()
        decrypted = decrypt_data(encrypted, key)
        return json.loads(decrypted)
    except:
        messagebox.showerror("Error", "Wrong master password or corrupted file.")
        return None

def capture_image_from_camera(title, output="captured.jpg"):
    cap = cv2.VideoCapture(0)
    if not cap.isOpened():
        messagebox.showerror("Camera Error", "Cannot access camera.")
        return None
    cv2.namedWindow(title)
    while True:
        ret, frame = cap.read()
        if not ret:
            break
        cv2.imshow(title, frame)
        key = cv2.waitKey(1)
        if key == ord('c'):
            cv2.imwrite(output, frame)
            cv2.imshow("Captured Image", frame)
            cv2.waitKey(1500)
            cv2.destroyWindow("Captured Image")
            break
        elif key == ord('q'):
            break
    cap.release()
    cv2.destroyAllWindows()
    return output

app = tk.Tk()
app.title("PhotonVault - Biometric Password Manager")
app.geometry("480x580")
app.resizable(False, False)

vault_data = {}
current_key = None

def save_master_password():
    pwd = setup_pwd_entry.get()
    confirm = confirm_pwd_entry.get()
    if not pwd or not confirm:
        messagebox.showwarning("Missing", "Enter and confirm password.")
        return
    if pwd != confirm:
        messagebox.showerror("Mismatch", "Passwords do not match.")
        return
    if len(pwd) < 6:
        messagebox.showwarning("Weak", "Use at least 6 characters.")
        return
    hashed = hashlib.sha256(pwd.encode()).hexdigest()
    with open(MASTER_FILE, "w") as f:
        f.write(hashed)
    messagebox.showinfo("Success", "Master password saved.")
    setup_frame.pack_forget()
    biometric_enroll_frame.pack(pady=30)

def enroll_biometrics():
    messagebox.showinfo("Step 1", "Look into the camera. Press 'c' to capture your IRIS.")
    iris = capture_image_from_camera("Capture Iris", "genuine_iris.jpg")
    if not iris:
        messagebox.showwarning("Failed", "Iris capture failed.")
        return
    messagebox.showinfo("Step 2", "Show your palm. Press 'c' to capture your PALM.")
    palm = capture_image_from_camera("Capture Palm", "genuine_palm.jpg")
    if not palm:
        messagebox.showwarning("Failed", "Palm capture failed.")
        return
    messagebox.showinfo("Success", "Biometric reference images saved.")
    biometric_enroll_frame.pack_forget()
    login_frame.pack(pady=30)

def login():
    global current_key, vault_data
    master = login_pwd_entry.get()
    if not master:
        messagebox.showwarning("Missing", "Enter master password.")
        return
    try:
        with open(MASTER_FILE) as f:
            stored_hash = f.read().strip()
    except:
        messagebox.showerror("Error", "Master password not found.")
        return
    if hashlib.sha256(master.encode()).hexdigest() != stored_hash:
        messagebox.showerror("Denied", "Incorrect master password.")
        return
    messagebox.showinfo("Capture Step", "Step 1: Position your eye and press 'c'")
    iris_input = capture_image_from_camera("Capture Iris", "temp_iris.jpg")
    messagebox.showinfo("Capture Step", "Step 2: Show your palm and press 'c'")
    palm_input = capture_image_from_camera("Capture Palm", "temp_palm.jpg")
    if not iris_input or not palm_input:
        messagebox.showerror("Failed", "Biometric capture failed.")
        return
    if not match_images("genuine_iris.jpg", iris_input) or not match_images("genuine_palm.jpg", palm_input):
        messagebox.showerror("Access Denied", "Biometric match failed.")
        return
    current_key = generate_key(master)
    data = load_encrypted_vault(current_key)
    if data is not None:
        vault_data.clear()
        vault_data.update(data)
        login_frame.pack_forget()
        vault_frame.pack(pady=10)
        messagebox.showinfo("Success", "Vault unlocked.")

def reset_master_password():
    messagebox.showinfo("Verify Identity", "To reset your password, verify your biometrics.")
    iris_input = capture_image_from_camera("Verify Iris", "temp_iris.jpg")
    palm_input = capture_image_from_camera("Verify Palm", "temp_palm.jpg")
    if not iris_input or not palm_input:
        messagebox.showerror("Failed", "Biometric capture failed.")
        return
    if not match_images("genuine_iris.jpg", iris_input) or not match_images("genuine_palm.jpg", palm_input):
        messagebox.showerror("Access Denied", "Biometric match failed. Cannot reset password.")
        return
    new_pwd = simpledialog.askstring("Reset Password", "Enter new master password:", show="*")
    if not new_pwd or len(new_pwd) < 6:
        messagebox.showwarning("Weak", "Use at least 6 characters.")
        return
    confirm_pwd = simpledialog.askstring("Confirm Password", "Confirm new master password:", show="*")
    if new_pwd != confirm_pwd:
        messagebox.showerror("Mismatch", "Passwords do not match.")
        return
    with open(MASTER_FILE, "w") as f:
        f.write(hashlib.sha256(new_pwd.encode()).hexdigest())
    messagebox.showinfo("Success", "Master password reset successful.")

def logout():
    global current_key, vault_data
    current_key = None
    vault_data.clear()
    vault_frame.pack_forget()
    login_pwd_entry.delete(0, tk.END)
    login_frame.pack(pady=30)
    messagebox.showinfo("Logged Out", "You are safely logged out.")

def add_entry():
    w = website_entry.get()
    u = username_entry.get()
    p = password_entry.get()
    if not all([w, u, p]):
        messagebox.showwarning("Empty", "Fill all fields.")
        return
    vault_data[w] = {"username": u, "password": p}
    save_encrypted_vault(vault_data, current_key)
    website_entry.delete(0, tk.END)
    username_entry.delete(0, tk.END)
    password_entry.delete(0, tk.END)
    messagebox.showinfo("Saved", f"{w} entry added.")

def delete_entry():
    w = website_entry.get()
    if w in vault_data:
        del vault_data[w]
        save_encrypted_vault(vault_data, current_key)
        messagebox.showinfo("Deleted", f"{w} removed.")
        view_vault()
    else:
        messagebox.showwarning("Not Found", "Website not found.")

def view_vault():
    result.delete(1.0, tk.END)
    if not vault_data:
        result.insert(tk.END, "Vault is empty.\n")
    for site, creds in vault_data.items():
        result.insert(tk.END, f"🌐 {site}\n  👤 {creds['username']}\n  🔑 {creds['password']}\n\n")

setup_frame = tk.Frame(app, padx=30, pady=30)
tk.Label(setup_frame, text="🔐 Setup Your Master Password", font=("Helvetica", 16, "bold"), fg="#007BFF").pack(pady=(0, 10))
tk.Label(setup_frame, text="Enter Master Password:", anchor="w", font=("Arial", 11)).pack(fill="x")
setup_pwd_entry = tk.Entry(setup_frame, show="*", width=30, font=("Arial", 11))
setup_pwd_entry.pack(pady=(0, 10))
tk.Label(setup_frame, text="Confirm Master Password:", anchor="w", font=("Arial", 11)).pack(fill="x")
confirm_pwd_entry = tk.Entry(setup_frame, show="*", width=30, font=("Arial", 11))
confirm_pwd_entry.pack(pady=(0, 10))
show_pwd_var = tk.BooleanVar()
def toggle_password():
    show = "" if show_pwd_var.get() else "*"
    setup_pwd_entry.config(show=show)
    confirm_pwd_entry.config(show=show)
tk.Checkbutton(setup_frame, text="Show Password", variable=show_pwd_var, command=toggle_password).pack(pady=(0, 15))
tk.Button(setup_frame, text="✅ Save Master Password", command=save_master_password, font=("Arial", 11), bg="#007BFF", fg="white", width=25).pack()

biometric_enroll_frame = tk.Frame(app)
tk.Label(biometric_enroll_frame, text="📸 Enroll Biometric Data", font=("Arial", 12)).pack(pady=10)
tk.Button(biometric_enroll_frame, text="Capture Iris & Palm", command=enroll_biometrics, width=25).pack(pady=10)

login_frame = tk.Frame(app)
tk.Label(login_frame, text="🔑 Enter Master Password", font=("Arial", 12)).pack(pady=10)
login_pwd_entry = tk.Entry(login_frame, show="*", width=30)
login_pwd_entry.pack(pady=5)
tk.Button(login_frame, text="Login with Biometrics", command=login, width=25).pack(pady=10)
tk.Button(login_frame, text="Forgot Password? Reset", command=reset_master_password, fg="blue").pack()

vault_frame = tk.Frame(app, padx=20, pady=20)
tk.Label(vault_frame, text="Website").grid(row=0, column=0)
tk.Label(vault_frame, text="Username").grid(row=1, column=0)
tk.Label(vault_frame, text="Password").grid(row=2, column=0)
website_entry = tk.Entry(vault_frame, width=30)
username_entry = tk.Entry(vault_frame, width=30)
password_entry = tk.Entry(vault_frame, width=30, show="*")
website_entry.grid(row=0, column=1)
username_entry.grid(row=1, column=1)
password_entry.grid(row=2, column=1)
tk.Button(vault_frame, text="➕ Add Entry", command=add_entry).grid(row=3, column=0, pady=10)
tk.Button(vault_frame, text="📂 View Vault", command=view_vault).grid(row=3, column=1, pady=10)
tk.Button(vault_frame, text="🗑️ Delete Entry", command=delete_entry).grid(row=3, column=2, padx=5)
result = tk.Text(vault_frame, height=10, width=50)
result.grid(row=4, column=0, columnspan=3, pady=10)
tk.Button(vault_frame, text="🚪 Logout", command=logout, bg="#d9534f", fg="white").grid(row=5, column=0, columnspan=3)

if not os.path.exists(MASTER_FILE):
    setup_frame.pack(pady=30)
elif not os.path.exists("genuine_iris.jpg") or not os.path.exists("genuine_palm.jpg"):
    biometric_enroll_frame.pack(pady=30)
else:
    login_frame.pack(pady=30)

app.mainloop()
