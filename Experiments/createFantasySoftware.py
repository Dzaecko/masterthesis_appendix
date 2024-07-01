import json
import os
import random

target_directory = r'C:\Users\Dzaecko\Downloads\cvelistV5-main\cvelistV5-main\mix'
if not os.path.exists(target_directory):
    os.makedirs(target_directory)

def generate_random_software_name():
    prefix = [
        'Ultra', 'Mega', 'Super', 'Hyper', 'Crypto',
        'Virtual', 'Quantum', 'NextGen', 'Advanced',
        'Pro', 'Easy', 'Cloud', 'Secure', 'Fast',
        'Smart', 'Power', 'Max', 'Dynamic', 'Auto',
        'Instant'
    ]
    keywords = [
        'nginx', 'mysql', 'apache', 'phpmyadmin', 'mariadb',
        'wordpress', 'drupal', 'samba', 'postgresql', 'postfix',
        'openssh', 'BIND', 'Exim', 'Squid', 'Dovecot',
        'vsftpd', 'proftpd', 'openvpn', 'gitea'
    ]
    middle = [
        'Backup', 'Security', 'Encryption', 'Storage', 'Database',
        'Networking', 'Monitoring', 'Analysis', 'Management', 'Recovery',
        'Compression', 'Messaging', 'Synchronization', 'Development', 'Testing'
    ]
    suffix = [
        'Tool', 'Utility', 'Suite', 'System', 'Service',
        'Hub', 'Engine', 'Gateway', 'Protector', 'Scanner'
    ]
    keyword_part = random.choice(keywords) + " " if random.choice([True, False]) else ""
    return f"{random.choice(prefix)} {keyword_part}{random.choice(middle)} {random.choice(suffix)}"

def generate_random_version():
    return f"{random.randint(1, 10)}.{random.randint(0, 9)}.{random.randint(0, 9)}"

for _ in range(500):
    software_name = generate_random_software_name()
    version = generate_random_version()
    data = {
        "Software": software_name,
        "Version": version,
        "VulnerabilityType": "None",
        "CVE-ID": "N/A"
    }
    
    filename = f"{software_name.replace(' ', '_').replace('.', '_').replace(',', '')}.json"
    filepath = os.path.join(target_directory, filename)
    
    with open(filepath, 'w') as file:
        json.dump(data, file, indent=4)

print(f"Es wurden 500 JSON-Dateien im Verzeichnis '{target_directory}' erstellt.")
