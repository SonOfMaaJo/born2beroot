*This project has been created as part of the 42 curriculum by vnaoussi.*

# Born2beRoot

## Description

Born2beRoot is a system administration project that introduces virtualization concepts. The objective is to set up a secure Debian server with strict partitioning (LVM/LUKS), a hardened sudo configuration, a strong password policy, and a monitoring script.

## Project Description: Technical Choices

### Debian vs Rocky Linux

For this project, a choice was made between Debian, a community-driven distribution known for its stability, and Rocky Linux, an enterprise-grade operating system based on RHEL. **Debian** was chosen for its balance of stability, ease of use, and vast community support.

#### Debian
*   **Pros:**
    *   **Stability:** Renowned for its very stable and reliable release cycle.
    *   **Community Support:** Has one of the largest communities, meaning extensive documentation, tutorials, and user support.
    *   **Package Management:** The `apt` package manager is widely considered user-friendly and efficient.
*   **Cons:**
    *   **Older Packages:** The focus on stability means that packages in the stable repository are often not the latest versions.

#### Rocky Linux
*   **Pros:**
    *   **Enterprise-Grade:** 100% compatible with Red Hat Enterprise Linux (RHEL), making it extremely robust for production environments.
    *   **Long-Term Support:** Benefits from the long support cycles inherent to enterprise distributions.
*   **Cons:**
    *   **Complexity:** Can be more complex to manage than Debian, especially for users not familiar with the RHEL ecosystem (e.g., `dnf`, `SELinux`).
    *   **Less Desktop-Friendly:** Historically more focused on server environments than on desktop use.

### AppArmor vs SELinux

For Mandatory Access Control (MAC), Debian defaults to AppArmor, while the RHEL ecosystem (Rocky Linux) uses SELinux. **AppArmor** was used for this project, aligning with the OS default and its simpler management philosophy.

#### AppArmor
*   **Pros:**
    *   **Ease of Use:** Profiles are simple text files with an intuitive syntax, making it much easier to learn and manage than SELinux.
    *   **Path-Based Logic:** Rules are based on file paths (e.g., `/usr/sbin/nginx`), which is straightforward to understand and debug.
    *   **Good Default Security:** Provides a significant security improvement over standard permissions with less administrative overhead.
*   **Cons:**
    *   **Less Granular:** Being path-based makes it less granular than SELinux. For instance, it can't easily distinguish between two different files if they are located at the same path.

#### SELinux (Security-Enhanced Linux)
*   **Pros:**
    *   **Extremely Granular:** Its label-based system (where every file and process has a security context) allows for incredibly detailed and powerful security policies.
    *   **Robustness:** Because it's not tied to paths, its security model is more robust against attempts to bypass rules by moving or renaming files.
*   **Cons:**
    *   **High Complexity:** Has a very steep learning curve. Writing and debugging SELinux policies is a specialized skill.
    *   **Troubleshooting:** Can be difficult to troubleshoot, leading many administrators to temporarily (and insecurely) disable it to solve problems.

### UFW vs firewalld

Both UFW and firewalld are frontends for managing the kernel's firewall capabilities. **UFW** was chosen for this project due to its straightforward approach, which is a perfect fit for a single server with static firewall needs.

#### UFW (Uncomplicated Firewall)
*   **Pros:**
    *   **Simplicity:** Designed to be extremely easy to use. The command syntax is simple and direct (e.g., `ufw allow ssh`).
    *   **Lightweight:** It's a simple script-based interface, not a constantly running daemon, which makes it very resource-efficient.
    *   **Ideal for Static Setups:** Perfect for servers or workstations where firewall rules do not change often.
*   **Cons:**
    *   **Less Flexible:** It lacks the concept of dynamic zones, making it less suitable for environments where network trust levels change frequently (like a laptop).
    *   **Requires Reload:** Rule changes typically require a reload of the firewall to be applied.

#### firewalld
*   **Pros:**
    *   **Dynamic Zones:** Its core feature allows assigning network interfaces to different zones (`public`, `home`, `trusted`), each with its own policy, which is highly flexible.
    *   **Runtime Changes:** Rules can be applied instantly without dropping existing connections, a major benefit for live servers.
    *   **Service Integration:** Well-integrated with system services, allowing rules like `add-service=http` without needing to know the port number.
*   **Cons:**
    *   **More Complex:** The concept of zones and the distinction between runtime vs. permanent configuration adds a layer of complexity.
    *   **Slightly More Overhead:** It runs as a background daemon, consuming more system resources than UFW.

### VirtualBox vs UTM

Choosing a hypervisor is crucial for virtualization projects. **VirtualBox** was selected for this project due to its widespread compatibility, ease of use across different host operating systems, and suitability for learning environments.

#### VirtualBox
*   **Pros:**
    *   **Cross-Platform Compatibility:** Runs on Windows, macOS, Linux, and Solaris hosts, making it highly versatile for different development environments.
    *   **Ease of Use:** Features a user-friendly graphical interface, making it accessible for beginners.
    *   **Widespread Adoption:** Large user base and extensive documentation available.
    *   **Free and Open Source:** Available at no cost for personal and educational use.
*   **Cons:**
    *   **Type 2 Hypervisor:** Runs on top of a host OS, which can introduce some performance overhead compared to Type 1 hypervisors.
    *   **Limited Advanced Features:** May lack some of the very advanced features found in enterprise-grade hypervisors (e.g., vMotion, sophisticated clustering).

#### UTM
*   **Pros:**
    *   **macOS Native:** Specifically designed for macOS, leveraging Apple's virtualization frameworks (e.g., Hypervisor.framework) for better performance on Apple Silicon Macs.
    *   **QEMU Backend:** Utilizes QEMU, allowing for both virtualization (running x86 VMs on Intel Macs) and emulation (running x86 VMs on Apple Silicon Macs).
    *   **Streamlined for macOS:** Integrates well with the macOS environment.
*   **Cons:**
    *   **macOS-Specific:** Limited to macOS hosts, which restricts its use to a single platform.
    *   **Steeper Learning Curve:** While user-friendly, setting up complex configurations or emulation can be more involved than VirtualBox.
    *   **Less Cross-Platform Support:** Not available on Windows or Linux hosts, making collaboration across different platforms more challenging.

### Apt vs Aptitude

On Debian-based systems, `apt` and `aptitude` are two primary package managers.

*   **`apt`**: The modern, standard command-line tool for managing packages. It is designed to be user-friendly and is sufficient for most everyday operations like installing, updating, and removing software.
*   **`aptitude`**: An older, more powerful package manager that features an interactive text-based UI and a more advanced dependency resolver. It excels at solving complex package conflicts by proposing multiple solutions.

**Conclusion:** For this project, `apt` is the default and recommended tool. `aptitude` remains a powerful alternative for advanced package management and debugging dependency issues.

---

### Partitioning Strategy (LVM and LUKS)

A robust and secure partitioning scheme was implemented using a combination of **LVM (Logical Volume Manager)** and **LUKS (Linux Unified Key Setup)** for encryption.

*   **LUKS Encryption**: The primary partition (`/dev/sda5`) is fully encrypted using LUKS. This provides full disk encryption, protecting data at rest from unauthorized access, especially crucial for sensitive information. A passphrase is required at boot to decrypt this partition.

*   **LVM**: On top of the LUKS-encrypted container (`sda5_crypt`), LVM is used to create flexible logical volumes. This allows for:
    *   **Dynamic Resizing**: Logical volumes can be easily resized, added, or removed without repartitioning the entire disk.
    *   **Snapshots**: LVM enables taking snapshots of logical volumes, useful for backups or testing system changes safely.

**Partition Layout:**

The disk is divided as follows, with critical directories separated into their own logical volumes for security, stability, and manageability:

```
NAME                    SIZE  TYPE  MOUNTPOINTS
sda                       30,8G disk
├─sda1                    476M part  /boot
├─sda2                    1K    part  (BIOS Boot Partition or similar)
└─sda5                    30,3G part  (LUKS Encrypted)
  └─sda5_crypt          30,3G crypt (LVM Physical Volume)
    ├─LVMGroup-root     9,3G  lvm   /
    ├─LVMGroup-swap     2,1G  lvm   [SWAP]
    ├─LVMGroup-var      2,8G  lvm   /var
    ├─LVMGroup-srv      2,8G  lvm   /srv
    ├─LVMGroup-tmp      2,8G  lvm   /tmp
    ├─LVMGroup-var--log 3,7G  lvm   /var/log
    └─LVMGroup-home     6,8G  lvm   /home
sr0                      1024M rom
```

**Rationale for Separate Partitions:**

*   **/boot**: A small, unencrypted partition is necessary for the GRUB bootloader to function.
*   **`/` (root)**: Contains the operating system files. A dedicated size ensures OS stability.
*   **SWAP**: Used as virtual memory. Its separate logical volume prevents it from interfering with other partitions.
*   **`/var`**: Holds variable data like logs, mail queues, and web server data. Separating it prevents runaway logs or web content from filling up the root partition.
*   **`/srv`**: Intended for data for services provided by the system (e.g., WordPress files in our bonus section). Keeping it separate isolates service data.
*   **`/tmp`**: For temporary files. Often mounted with specific security options (e.g., `noexec`, `nosuid`) and cleared on reboot. Its separation prevents temporary files from impacting system stability.
*   **`/var/log`**: Dedicated solely to system logs. This prevents excessive log growth from filling `/var` or `/` and allows for easier log management.
*   **`/home`**: Stores user home directories. Separating it ensures user data is isolated from the operating system, simplifying backups and system reinstalls.

---

## Instructions

### 1. SSH Installation and Configuration
SSH (Secure Shell) allows secure remote access to the server.

**Installation:**
```bash
sudo apt update
sudo apt install openssh-server
```

**Configuration:**
1.  Open the configuration file:
    ```bash
    sudo nano /etc/ssh/sshd_config
    ```
2.  Locate the line `#Port 22` and change it to `Port 4242`.
3.  Locate the line `#PermitRootLogin prohibit-password` and change it to `PermitRootLogin no`.
4.  Save and exit (`Ctrl+O`, `Enter`, `Ctrl+X`).
5.  Restart the SSH service:
    ```bash
    sudo systemctl restart ssh
    ```

**Verification:**
*   Check service status: `sudo systemctl status ssh`
*   Check listening port: `ss -tunlp | grep 4242`

**Client-Side Connection Setup:**
To connect securely without typing a password every time:

1.  **Generate an SSH Key Pair (on your host machine):**
    ```bash
    ssh-keygen
    ```
    *(Press Enter to accept defaults)*

2.  **Send the Public Key to the Server:**
    Replace `user` with your server username and `IP_ADDRESS` with the VM's IP.
    ```bash
    ssh-copy-id -p 4242 user@IP_ADDRESS
    ```

3.  **Connect:**
    ```bash
    ssh user@IP_ADDRESS -p 4242
    ```

**File Transfer with SCP:**
To send files from your host machine to the server:
```bash
scp -P 4242 /path/to/local/file user@IP_ADDRESS:/path/to/destination/
```
*Note: Use `-P` (uppercase) for the port with `scp`.*

---

### 2. UFW Firewall Configuration
UFW (Uncomplicated Firewall) is used to manage incoming and outgoing traffic.

**Installation and Activation:**
```bash
sudo apt update
sudo apt install ufw
sudo ufw enable
```

**Managing Rules:**
1.  **Allow SSH port (4242):**
    ```bash
    sudo ufw allow 4242
    ```
2.  **Allow HTTP (80) - for Bonus:**
    ```bash
    sudo ufw allow 80
    ```
3.  **Check Status and Rules:**
    ```bash
    sudo ufw status verbose
    ```
4.  **Delete a Rule:**
    First, get the rule number:
    ```bash
    sudo ufw status numbered
    ```
    Then, delete it (replace `X` with the number):
    ```bash
    sudo ufw delete X
    ```

**Verification:**
*   `sudo ufw status` should show "active" and the allowed ports.

---

### 3. User and Group Management & Hostname

#### A. User Management

**`adduser` vs `useradd` (Important for Defense):**
*   **`adduser` (Recommended):** A high-level Perl script. It is interactive and user-friendly. It automatically creates the home directory, copies skeleton files (`.bashrc`), sets the default shell (`/bin/bash`), and prompts for a password and user details.
*   **`useradd`:** A low-level binary. By default, it creates a user **without** a home directory and **without** a password (account locked). You must specify options manually (e.g., `-m` for home, `-s` for shell).

**Creating a New User (Interactive - Recommended):**
```bash
sudo adduser new_username
```
*(You will be prompted to set a password and user details like Full Name, Room Number, etc.)*

**Creating a New User (Low Level - Manual):**
```bash
sudo useradd -m -s /bin/bash new_username
sudo passwd new_username  # You MUST set a password manually afterwards
```

**Modifying a Password:**
To change a user's password manually (or root's):
```bash
sudo passwd username
```

**Password Aging (Chage):**
To verify password expiration rules for a specific user:
```bash
sudo chage -l username
```

**Deleting a User:**
```bash
sudo deluser --remove-home username
```

#### B. Group Management
**Creating a New Group:**
```bash
sudo addgroup groupname
```

**Assigning a User to a Group:**
```bash
sudo usermod -aG groupname username
```
*(Note: `-aG` appends the user to the group without removing them from others)*

**Removing a User from a Specific Group:**
```bash
sudo deluser username groupname
```
*(Removes the user from the specified group only, keeps the user account)*

**Verifying User Groups:**
```bash
id username
# OR
getent group groupname
```

**Deleting a Group:**
```bash
sudo delgroup groupname
```

#### C. Hostname Management
The hostname is your machine's network name (must be `login42`).

**Verification:**
```bash
hostnamectl
```

**Modification:**
1.  Change the system hostname:
    ```bash
    sudo hostnamectl set-hostname new_hostname
    ```
2.  **Important:** You must also edit the hosts file to map the new name to localhost:
    ```bash
    sudo nano /etc/hosts
    ```
    *Find the line `127.0.0.1 old_hostname` and replace it with `127.0.0.1 new_hostname`.*
3.  Reboot is recommended (`sudo reboot`).

#### D. Critical Configuration Files
Understanding where user/group data is stored is essential.

*   `/etc/passwd`: Contains user account information (User ID, Group ID, Home Dir, Shell). readable by all.
*   `/etc/shadow`: Contains **encrypted passwords** and password expiration information. Readable only by root (Security).
*   `/etc/group`: Defines the groups on the system and lists their members.
*   `/etc/gshadow`: Contains encrypted group passwords (rarely used) and group administrator information.
*   `/etc/sudoers`: Defines who can run commands as root. **Always edit with `sudo visudo`**.

---

### 4. Sudo Configuration
Sudo rules are defined in `/etc/sudoers` using `visudo`.

**Requirements:**
*   3 attempts limit.
*   Custom error message.
*   Log all inputs/outputs in `/var/log/sudo/`.
*   TTY mode enabled.
*   Secure paths restricted.

**Configuration:**
```bash
sudo visudo
```
Add these lines:
```text
Defaults    passwd_tries=3
Defaults    badpass_message="Custom error message here"
Defaults    logfile="/var/log/sudo/sudo.log"
Defaults    log_input, log_output
Defaults    iolog_dir="/var/log/sudo"
Defaults    requiretty
Defaults    secure_path="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
```

---

### 5. Password Policy
Managed via `/etc/login.defs` and `libpam-pwquality`.

**Installation:**
```bash
sudo apt install libpam-pwquality
```

**Complexity Rules (`/etc/pam.d/common-password`):**
```text
password requisite pam_pwquality.so retry=3 minlen=10 ucredit=-1 lcredit=-1 dcredit=-1 maxrepeat=3 reject_username difok=7 enforce_for_root
```

**Expiration Rules (`/etc/login.defs`):**
```text
PASS_MAX_DAYS   30
PASS_MIN_DAYS   2
PASS_WARN_AGE   7
```
**Important Note:**
Editing `/etc/login.defs` only affects **newly created users**. To apply these rules to existing users (and root), you must use the `chage` command manually:
```bash
sudo chage -M 30 <username>
sudo chage -m 2 <username>
sudo chage -W 7 <username>
```
*(Repeat for `root` as well)*

---

### 6. Monitoring Script

The `monitoring.sh` script is designed to display system information on all terminals every 10 minutes.

**1. Installation**
1.  Create the script file:
    ```bash
    sudo nano /usr/local/bin/monitoring.sh
    ```
2.  Paste the script content and save.
3.  Make it executable:
    ```bash
    sudo chmod +x /usr/local/bin/monitoring.sh
    ```

**2. Cron Configuration**
To run the script every 10 minutes starting from server boot:

1.  Open the root crontab:
    ```bash
    sudo crontab -e
    ```
2.  Add the following line at the end of the file:
    ```cron
    */10 * * * * /usr/local/bin/monitoring.sh
    ```
3.  Save and exit. The script will now run automatically.

**3. Verification**
*   To test the script immediately: `sudo /usr/local/bin/monitoring.sh`
*   To check cron logs: `grep CRON /var/log/syslog` (on Debian)

---

## Partie Bonus : Serveur Web WordPress

Cette section bonus détaille la mise en place d'un serveur web complet pour héberger un site WordPress sur la machine virtuelle.

### Stack Technique

Pour ce déploiement, nous utilisons une stack légère et performante, en évitant les serveurs plus lourds comme Apache ou Nginx :

*   **Lighttpd** : Un serveur web très léger et rapide. Son rôle est de recevoir les requêtes des visiteurs et de servir les fichiers statiques (CSS, images). Il ne peut pas exécuter de code PHP lui-même.
*   **PHP-FPM** (FastCGI Process Manager) : Le moteur qui exécute le code PHP de WordPress. Quand Lighttpd reçoit une requête pour une page PHP, il la transmet à PHP-FPM, qui génère la page et la renvoie au serveur web.
*   **MariaDB** : Le système de gestion de base de données. WordPress y stocke tout son contenu : articles, pages, utilisateurs, commentaires, et configurations.

### Étapes d'Installation et de Configuration

#### 1. Installation des Paquets

Installez tous les logiciels nécessaires via `apt`.

```bash
sudo apt update
sudo apt install lighttpd mariadb-server php-fpm php-mysql php-gd php-intl php-zip
```

#### 2. Configuration de PHP-FPM

Nous devons activer des extensions PHP indispensables pour WordPress.

1.  **Ouvrez le fichier de configuration de PHP-FPM** (attention à bien prendre celui pour FPM, et non pour CLI) :
    ```bash
    # Le chemin peut varier selon la version, par ex. /etc/php/8.2/fpm/php.ini
    sudo nano /etc/php/8.4/fpm/php.ini
    ```

2.  **Activez les extensions** en retirant le point-virgule (`;`) au début des lignes suivantes :
    ```ini
    extension=gd
    extension=iconv
    extension=mysqli
    extension=pdo_mysql
    extension=zip
    ```

> ##### À quoi servent ces extensions ?
> *   **`mysqli` / `pdo_mysql`** : Permettent à PHP de communiquer avec la base de données MariaDB. Indispensable pour lire ou écrire des données.
> *   **`gd`** : Bibliothèque de traitement d'images, utilisée par WordPress pour créer des miniatures et redimensionner les images.
> *   **`zip`** : Permet l'installation et la mise à jour des thèmes et plugins, qui sont fournis en format `.zip`.
> *   **`iconv`** : Assure la bonne gestion des jeux de caractères pour les langues et les accents.

#### 3. Configuration de MariaDB

1.  **Lancez le script de sécurisation initial** :
    ```bash
    sudo mysql_secure_installation
    ```
    *(Suivez les instructions pour définir un mot de passe root et sécuriser l'installation).*

2.  **Connectez-vous à MariaDB** en tant que root :
    ```bash
    sudo mariadb -u root -p
    ```

3.  **Créez la base de données et l'utilisateur** pour WordPress :
    ```sql
    CREATE DATABASE wordpress;
    CREATE USER 'wp_user'@'localhost' IDENTIFIED BY 'motdepasse_solide';
    GRANT ALL PRIVILEGES ON wordpress.* TO 'wp_user'@'localhost';
    FLUSH PRIVILEGES;
    EXIT;
    ```
    *(Pensez à utiliser un mot de passe plus sécurisé que `motdepasse_solide`)*.

#### 4. Installation de WordPress

1.  **Créez le répertoire** qui hébergera le site et naviguez dedans :
    ```bash
    sudo mkdir -p /srv/wordpress/html
    cd /srv/wordpress/html
    ```

2.  **Téléchargez et extrayez** la dernière version de WordPress :
    ```bash
    sudo wget https://wordpress.org/latest.tar.gz
    sudo tar -xzvf latest.tar.gz
    sudo mv wordpress/* .
    sudo rm -rf wordpress latest.tar.gz
    ```

3.  **Définissez les bonnes permissions** pour que le serveur web puisse gérer les fichiers :
    ```bash
    sudo chown -R www-data:www-data /srv/wordpress/html/
    ```
    *(Note : Sur Debian, l'utilisateur du serveur web est `www-data`, pas `http`).*

#### 5. Configuration de Lighttpd

1.  **Ouvrez le fichier de configuration** de Lighttpd :
    ```bash
    sudo nano /etc/lighttpd/lighttpd.conf
    ```

2.  **Modifiez le `server.document-root`** pour qu'il pointe vers votre dossier WordPress :
    ```lighttpd
    server.document-root    = "/srv/wordpress/html/"
    ```

3.  **Activez le module `mod_fastcgi`** (il est souvent déjà dans la liste `server.modules`).

4.  **Ajoutez la configuration pour lier PHP-FPM**. Sur Debian, il est recommandé d'utiliser un fichier de configuration séparé. Activez la configuration PHP :
    ```bash
    sudo lighty-enable-mod fastcgi-php
    ```
    *Cela crée un lien symbolique et ajoute la configuration nécessaire.*

#### 6. Démarrage et Activation des Services

Activez les services pour qu'ils se lancent au démarrage et démarrez-les maintenant.

```bash
# Le nom du service peut varier, ex: php8.2-fpm
sudo systemctl enable --now lighttpd php8.4-fpm mariadb
```

Vous pouvez maintenant finaliser l'installation en accédant à l'adresse IP de votre VM dans un navigateur.

### Vérification de l'installation

Voici quelques commandes pour vérifier que tout fonctionne comme prévu :

*   **Statut des services** :
    ```bash
    systemctl status lighttpd php8.4-fpm mariadb
    ```
*   **Ports d'écoute** (devrait montrer les ports 80, 3306) :
    ```bash
    ss -tlpn
    ```
*   **Extensions PHP activées** (devrait retourner 5 lignes) :
    ```bash
    grep -E '^extension=(gd|iconv|mysqli|pdo_mysql|zip)' /etc/php/8.4/fpm/php.ini
    ```
*   **Connexion à la base de données** :
    ```bash
    mariadb -u wp_user -p
    ```
*   **Permissions des fichiers WordPress** (propriétaire `www-data`) :
    ```bash
    ls -l /srv/wordpress/html/
    ```

---

### FTP Service with vsftpd (Bonus)

**Why use vsftpd?**
vsftpd (Very Secure FTP Daemon) is an FTP server that allows you to upload and manage files on your server from your host machine. This is particularly useful for managing your WordPress site (uploading themes, plugins, or editing configuration files) using a graphical client like FileZilla, rather than using the command line for everything.

#### 1. Installation and Firewall
```bash
sudo apt install vsftpd
sudo ufw allow 21/tcp
sudo ufw allow 40000:40005/tcp
sudo ufw reload
```

#### 2. Configuration
1.  Edit the configuration file:
    ```bash
    sudo nano /etc/vsftpd.conf
    ```
2.  Ensure the following settings are set (uncomment or add them) to enable uploads and secure the connection:
    ```ini
    local_enable=YES
    write_enable=YES
    chroot_local_user=YES
    allow_writeable_chroot=YES
    pasv_min_port=40000
    pasv_max_port=40005
    # Optional: Direct access to WordPress folder
    local_root=/srv/wordpress/html
    ```
3.  Restart the service:
    ```bash
    sudo systemctl restart vsftpd
    ```

#### 3. Permissions for WordPress Management
To allow your user to modify WordPress files via FTP, add them to the web server group:
```bash
# Replace 'your_username' with your actual username
sudo usermod -aG www-data your_username
sudo chown -R www-data:www-data /srv/wordpress/html
sudo chmod -R 775 /srv/wordpress/html
```
*(You may need to logout and login again for group changes to take effect).*

#### 4. Accessing via FileZilla
*   **Host:** Your VM IP Address
*   **Protocol:** FTP - File Transfer Protocol
*   **Encryption:** Require explicit FTP over TLS (Recommended)
*   **User/Password:** Your VM credentials

---

### Fail2Ban Protection (Bonus)

**Why use Fail2Ban?**
Fail2Ban is an intrusion prevention software framework that protects computer servers from brute-force attacks. It works by monitoring system logs (e.g., `/var/log/auth.log`) for suspicious activity, such as too many failed login attempts. When it detects such behavior, it updates the firewall rules to reject new connections from those IP addresses for a configurable amount of time.

#### 1. Installation and Activation
```bash
sudo apt update
sudo apt install fail2ban
sudo systemctl enable --now fail2ban
```

#### 2. Configuration
It is recommended to use a `jail.local` file instead of modifying `jail.conf` directly to prevent updates from overwriting your changes.

1.  **Create the local configuration file:**
    ```bash
    sudo cp /etc/fail2ban/jail.conf /etc/fail2ban/jail.local
    ```

2.  **Configure for SSH:**
    ```bash
    sudo nano /etc/fail2ban/jail.local
    ```
    *Locate the `[sshd]` section and ensure it points to your custom SSH port:*
    ```ini
    [sshd]
    enabled = true
    port    = 4242
    logpath = %(sshd_log)s
    backend = %(sshd_backend)s
    maxretry = 3
    bantime = 10m
    ```

3.  **Restart the service:**
    ```bash
    sudo systemctl restart fail2ban
    ```

#### 3. Verification and Usage
Here is how to check if Fail2Ban is working correctly:

*   **General Status:**
    ```bash
    sudo fail2ban-client status
    ```
*   **Specific Status for SSH** (to see currently banned IPs):
    ```bash
    sudo fail2ban-client status sshd
    ```
*   **Check Logs:**
    ```bash
    sudo tail -f /var/log/fail2ban.log
    ```
*   **Manually Unban an IP:**
    ```bash
    sudo fail2ban-client set sshd unbanip <IP_ADDRESS>
    ```

---

## AI Usage

Artificial Intelligence was used to structure and ensure the coherence of this README, as well as to troubleshoot installation and connection issues related to the various services installed on the server.

---

## Resources

*   [Debian Documentation](https://www.debian.org/doc/)
*   [Sudo Manual](https://www.sudo.ws/docs/man/1.8.17/sudoers.man/)
*   [AppArmor Wiki](https://gitlab.com/apparmor/apparmor/-/wikis/home)
*   [UFW Documentation](https://help.ubuntu.com/community/UFW)

---
