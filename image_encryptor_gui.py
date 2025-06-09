import tkinter as tk
from tkinter import filedialog, messagebox
from PIL import Image, ImageTk
import hashlib                                              #hier importeren we allemaal andere stukjes code om in onze code te gebruiken zodat we dat niet hier hoeven te schrijven.
from cryptography.fernet import Fernet
import base64
import threading
import os
import socket

# -------------------- Utility Functions --------------------
                                                            #hier defineren wij functies om later te gebruiken
def generate_key(password: str) -> Fernet:                  #dit genereerd de encryptiesleutel aan de hand van je wachtwoord
    hashed = hashlib.sha256(password.encode()).digest()     #dit wachtwoord word gehashed met SHA-256 en de hash word als bytes neergezet door de .digest
    return Fernet(base64.urlsafe_b64encode(hashed))         #deze hash in bytes wordt omgezet naar base64 voor fernet

def encrypt_file(filepath, password):                       #hier word eigenlijk gezegd: oke als ik dit zometeen zeg ( encrypt_file ) dan moet jij het volgende doen ( wat eronder staat ) met deze dingen (filepath en password)
    with open(filepath, 'rb') as f:
        data = f.read()                                     #leest de foto in als bytes
    fernet = generate_key(password)                         #genereed de key met de functie die we hiervoor gedefineerd hebben
    return fernet.encrypt(data)                             #encrypt de data met 

def decrypt_data(data, password):
    fernet = generate_key(password)                         #hier word met hetzelfde ingevoerde wachtwoord de key gegenereerd met de functie die we eerder hebben gedefineerd.
    return fernet.decrypt(data)                             #hier word de zojuist gegenereerde key gebruikt om met de fernet functie de foto te decrypten.

# -------------------- GUI Application --------------------

class ImageEncryptorApp:                                    #de hoofdclasse die de gui beheert
    def __init__(self, root):                               #deze _init_ is de soort start van de hele code of het programma om het zo te noemen
        self.root = root                                    #hier bewaren wij het venster object. dit zijn ook fucnties van Tkinter library
        self.root.title("Image Encryptor & Secure Sender")  #hier geven we het programma de titel die bovenaan het venster komt te staan
        self.file_path = None                               # dit reset de variabel file path naar een soort NULL

        # Mode selection
        self.mode_var = tk.StringVar(value="send")                                                          #hier word de waarde van het sturen of ontvangen bijgehouden in een variable van de TKinter library
        tk.Radiobutton(root, text="Send", variable=self.mode_var, value="send").pack(anchor='w')            # hier maak je de knop voor de mode selectie send
        tk.Radiobutton(root, text="Receive", variable=self.mode_var, value="receive").pack(anchor='w')      # dit is de knop voor de mode receive

        # File selection (Send mode only)
        tk.Button(root, text="Choose Image", command=self.choose_file).pack()       #hier word de functie omschreven voor de knop om de foto te selecteren.
        self.file_label = tk.Label(root, text="No file selected")                   # dit is de standaardtext die word laten zien maar dit kan later aangepast worden ( we maken een variabel aan en geven dit variable een waarde of dus ee naam maar bij het kiezen van een foto passen we dus deze variable weer aan)
        self.file_label.pack()                                                      # de .pack zet het label op het scherm

        # IP and Port fields
        self.ip_entry = self.labeled_entry("IP Address (for sending):")             #dit zijn entry's dus waar je iets kunt invoeren en daarna word gezegd labeled entry om de titel te geven
        self.port_entry = self.labeled_entry("Port:")                               #

        # Password field
        self.pwd_entry = self.labeled_entry("Password:", show="*")                  #dit is eigenlijk hetzelfde als de vorige 2 regels met dus self.pwd_entry om de naam te geven in de code om later te gebruiken en een titel in de gui en ook nog schow="*" zodat het wachtwoord word verschuilt

        # Action button
        tk.Button(root, text="Start", command=self.start_action).pack(pady=10)      #dit is de knop die de command start.action uitvoerd.

        # Image display
        self.image_label = tk.Label(root)               # hier word een veld gemaakt waar we later een afbeelding in kunnen tonen
        self.image_label.pack()                         #

    def labeled_entry(self, label, show=None):          # labeled_entry defineeren je snapt het
        tk.Label(self.root, text=label).pack()          #hier maken we gewoon een velde voor text aan zodat we dat kunnen gebruiken bij elke invulveld zoals wachtwoord of andere dingen
        entry = tk.Entry(self.root, show=show)          #
        entry.pack()
        return entry

    def choose_file(self):                                                                                              #choose file defineren blbla je snapt het
        self.file_path = filedialog.askopenfilename(filetypes=[("Image files", "*.jpg;*.png;*.jpeg;*.bmp")])            #hier word eerst een venster geopend om je bestand te selecteren met filedialog.askopenfilename en daarna welke bestandtypes het mogen zijn.
        self.file_label.config(text=os.path.basename(self.file_path) if self.file_path else "No file selected")         #hier word de naam van het bestand achterhaald en als er niks staat bij de naam word er no file selected laten zien

    def start_action(self):                 #hier defineren we de actie om de foto te sturen
        mode = self.mode_var.get()          #hier "pakken" we alle info die we nodig hebben dus sturen of ontvangen, het wachtwoord en de port
        password = self.pwd_entry.get()     # 
        port = int(self.port_entry.get())   #

        if mode == "send":                                                                  #
            if not self.file_path or not os.path.exists(self.file_path):                    #als er geen foto of juist bestand of uberhaubt geen bestand gekozen word deze error laten zien
                messagebox.showerror("Error", "Please select a valid image file.")          #
                return                                                                      #
            ip = self.ip_entry.get()                                                        #dit kan je vergelijken met de 3 lines aan het begin van deze def
            threading.Thread(target=self.send_file, args=(ip, port, password)).start()      #hier staat gewoon als send file is geselecteerd dan stuur je met de opgehaalde info het bestand
        else:                                                                               #
            threading.Thread(target=self.receive_file, args=(port, password)).start()       #hier staat hetzelfde maar dan als er receive staat dan moet je receiven zegmaar

    def send_file(self, ip, port, password):                                    #hier defineren we dus wat er gedaan moet worden als er send_file gezegd word
        try:                                                                    #
            encrypted_data = encrypt_file(self.file_path, password)             #hier geven we gewoon aan wat encrypted data is
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:        #hier geven wat dingen aan voor het versturen namelijk AF.INET vor ipv4 en socket stream voor TCP
                s.connect((ip, port))                                           #dit verbind met de server
                s.sendall(encrypted_data)                                       #en dit zegt gewoon stuur alles
            messagebox.showinfo("Success", "File sent successfully!")           #als het lukte dan word dit laten zien
        except Exception as e:                                                  #als het niet lukt word deze error laten zien
            messagebox.showerror("Error", str(e))                               #

    def receive_file(self, port, password):                                             #hier defineren wij de receive file functie bla bla je snpat het wel
        try:                                                                            #
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:           # hier zeggen we hetzelfde zoals bij de send_files maar nu staat er dus as server ( om te ontvangen dus )
                server.bind(('', port))                                                 #hier luistert de server ( ontvanger ) op de aangeduide port
                server.listen(1)                                                        #
                conn, _ = server.accept()                                               #   de server luistert dus voor de zender hier om te connecten
                with conn:                                                              #dit gebeurd er dus als de connectie gelukt is
                    received_data = b""                                                 # 
                    while True:                                                         #hier ontvangt het programma steeds 4096 bytes en als er geen data meer is dan is het bericht klaar
                        chunk = conn.recv(4096)                                         #
                        if not chunk:                                                   #
                            break                                                       # dus als de data minder dan 4096 bytes is stopt de overdracht
                        received_data += chunk                                          #

            decrypted = decrypt_data(received_data, password)   # hier zeg je dat decrypted  de decrypted data is van de received data met de password
            output_path = "received_image.jpg"                  # je maakt een variable aan met de naam received_image.jpg
            with open(output_path, 'wb') as f:                  # hier word een bestand aangemaakt in het output_path
                f.write(decrypted)                              # en hier schrijf je de decrypted in het zojuist aangemaakte bestand.

            self.display_image(output_path)                                                 # geef de afbeelding weer in het output path
            messagebox.showinfo("Success", f"Image received and saved as {output_path}")    #geef aan of het succesvol ging of niet met een messege
        except Exception as e:                                                              #
            
            messagebox.showerror("Error", f"Failed to receive/decrypt image:\n{str(e)}")    #

    def display_image(self, path):                  # define display van de foto yatata je snapt het
        img = Image.open(path)                      # de image is de de image met het opgegeven pad
        img.thumbnail((400, 400))                   # de preview(thumbnail) dimensies aanduiden
        tk_img = ImageTk.PhotoImage(img)            # photoimage maakt de image geschikt voor Tkinter
        self.image_label.configure(image=tk_img)    # hier word het label verandert naar de naam van de image
        self.image_label.image = tk_img             

# -------------------- Run App --------------------

if __name__ == "__main__":          #start het script als het main heet
    root = tk.Tk()                  #maakt het hoofdvenster
    app = ImageEncryptorApp(root)   #start de app
    root.mainloop()                 #dit houd de GUI running tot je het sluit
