# SecureVault 🔒

Hey! This is **SecureVault**, a project I built to keep files truly private. I wanted a way to store my sensitive documents where they’re protected by more than just a login—they're actually scrambled so that even the server can't read them without my password.

## What is this?
Basically, it's a digital safe for your files. When you upload something, the app turns it into unreadable gibberish using **AES-256 encryption** (the gold standard) before saving it. 

The neat part? Your encryption key is never stored. It’s generated from your password the moment you need it, and it disappears as soon as the task is done. 

## Features that make it awesome
*   **Truly Secure:** Every file gets its own unique "lock" and "key." Even if someone stole the database, they wouldn't find anything but encrypted blocks.
*   **Fast & Clean:** I used **FastAPI** to keep things snappy and built a sleek, dark-mode dashboard that’s easy to use.
*   **Tamper Proof:** If even a single byte of an encrypted file is changed behind the scenes, the app detects it and blocks it.
*   **Smart Logging:** It keeps a simple audit log so you can see when someone logged in or accessed a file.
*   **Built-in Safety:** It has rate limiting (to stop hackers from guessing passwords) and CSRF protection (to prevent malicious website attacks).

## Getting Started

If you want to run this locally, it's pretty straightforward.

### 1. Install the basics
Make sure you have Python installed, then grab the dependencies:
```bash
pip install -r requirements.txt
```

### 2. Launch the vault
Start the server with this command:
```bash
uvicorn app.main:app --reload
```
Now just head over to `http://localhost:8000` and you're good to go!

### 3. (Optional) Configuration
If you want to customize things (like the folder where files are stored or the max file size), you can create a `.env` file. Check out `.env.example` to see how.

## How it's built
*   **`app/`**: The core web logic and database stuff.
*   **`crypto/`**: The "secret sauce"—all the encryption math lives here.
*   **`storage/`**: Handles the dirty work of reading and writing encrypted files to your disk.
*   **`templates/` & `static/`**: This is what makes the site look pretty and feel responsive.

## Why did I build this?
I wanted to see if I could build a "zero-knowledge" style storage system where I didn't have to trust the storage provider (even if that provider is just me on my own computer!). It was a fun challenge to get the security right while keeping the UI feeling modern and simple.

---

**Note:** If you're planning to use this for real, remember to use a strong password—since I don't store your keys, there's no "Forgot Password" button here!

---
*Built with care and a lot of testing.*
<img width="1920" height="872" alt="SecureVault — Encrypted File Storage - Brave 11-03-2026 17_48_39" src="https://github.com/user-attachments/assets/dc30c4fc-cead-4384-939a-7dfed6a53206" />

<img width="1920" height="866" alt="SecureVault — Encrypted File Storage - Brave 11-03-2026 17_48_53" src="https://github.com/user-attachments/assets/538a0e47-e4a4-4ac7-85a9-2bfb823ce97a" />

<img width="1920" height="876" alt="SecureVault — Encrypted File Storage - Brave 11-03-2026 17_49_03" src="https://github.com/user-attachments/assets/e2b85df2-791e-4e26-9b2f-c9e32500fbb6" />

<img width="1920" height="879" alt="SecureVault — Encrypted File Storage - Brave 11-03-2026 17_49_20" src="https://github.com/user-attachments/assets/dc02279b-0c84-484a-b8e5-edcade914300" />





