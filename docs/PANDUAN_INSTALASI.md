# Panduan Instalasi dan Penggunaan LUINT

## Daftar Isi
1. [Persyaratan Sistem](#persyaratan-sistem)
2. [Instalasi](#instalasi)
3. [Konfigurasi](#konfigurasi)
4. [Penggunaan Dasar](#penggunaan-dasar)
5. [Penggunaan Modul](#penggunaan-modul)
6. [Output dan Pelaporan](#output-dan-pelaporan)
7. [Pemecahan Masalah](#pemecahan-masalah)

## Persyaratan Sistem

- Python 3.8 atau lebih baru
- Sistem operasi: Windows, macOS, atau Linux
- Koneksi internet untuk fitur pencarian yang bergantung pada API eksternal
- Setidaknya 2GB RAM dan 500MB ruang disk
- Nmap (diperlukan untuk pemindaian port dan deteksi layanan)

### Instalasi Nmap

Nmap diperlukan untuk modul server_info. Untuk menginstal:

```bash
# Di Linux
sudo apt-get install nmap

# Di macOS
brew install nmap

# Di Windows
# Unduh installer dari nmap.org
```

## Instalasi

### 1. Clone repositori
```bash
git clone https://github.com/pixelbrow720/luint.git
cd luint
```

### 2. Buat virtual environment (opsional tetapi direkomendasikan)
```bash
python -m venv venv
```

Aktifkan virtual environment:
- Di Windows:
  ```
  venv\Scripts\activate
  ```
- Di macOS/Linux:
  ```
  source venv/bin/activate
  ```

### 3. Instal dependensi
Metode 1 (Direkomendasikan) - Instalasi sebagai paket yang dapat diedit:
```bash
pip install -e .
```

Metode 2 - Instalasi dari requirements:
```bash
pip install -r requirements.txt
```

### 4. Verifikasi instalasi
```bash
python main.py --version
```

### Pemecahan Masalah Instalasi

#### Kesalahan Multiple Top-level Packages

Jika Anda mengalami error seperti:
```
error: Multiple top-level packages discovered in a flat-layout: ['logs', 'luint', 'wordlists'].
```

Ada beberapa solusi:

1. **Gunakan flag `--no-build-isolation`**:
   ```bash
   pip install --no-build-isolation -e .
   ```

2. **Instalasi langsung dari requirements.txt**:
   ```bash
   pip install -r requirements.txt
   ```

3. **Pastikan struktur direktori benar**:
   - Direktori `logs` dan `wordlists` harus ada 
   - Jika error tetap berlanjut, Anda bisa mencoba menciptakan struktur src-layout:
     ```bash
     mkdir -p src
     mv luint src/
     ```
     Kemudian perbarui pyproject.toml:
     ```toml
     [tool.setuptools]
     package-dir = {"" = "src"}
     packages = ["luint"]
     ```

#### Kesalahan ModuleNotFoundError

Jika program berjalan tetapi Anda melihat `ModuleNotFoundError`, pastikan:

1. Virtual environment sudah diaktifkan
2. Instalasi berhasil tanpa error
3. Anda menjalankan program dari direktori root proyek

Coba install ulang dengan:
```bash
pip install -e .
```

## Konfigurasi

LUINT menggunakan file `config.yaml` untuk mengkonfigurasi berbagai aspek aplikasi. Anda dapat menyalin dari contoh yang disediakan:

```bash
cp config.yaml.example config.yaml
```

### Struktur File Konfigurasi

```yaml
general:
  cache_duration: 3600  # Durasi cache dalam detik
  threads: 10           # Jumlah maksimum thread
  timeout: 30           # Timeout permintaan default
  user_agent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
  
modules:
  dns_info:
    dns_servers: ['8.8.8.8', '1.1.1.1']
    timeout: 5
    check_dnssec: true
    
  server_info:
    ports: [80, 443, 8080, 8443]
    scan_timeout: 5
    detect_waf: true
    ssl_check: true
    perform_advanced_port_scan: false  # Atur ke true untuk pemindaian kerentanan komprehensif
  
  subdomain_enum:
    wordlist: 'wordlists/subdomains.txt'
    max_subdomains: 1000
    
  content_discovery:
    directories_wordlist: 'wordlists/directories.txt'
    files_wordlist: 'wordlists/files.txt'
    max_depth: 3
    threads: 20

api_keys:
  shodan: "YOUR_SHODAN_API_KEY"
  censys: "YOUR_CENSYS_API_KEY"
  virustotal: "YOUR_VIRUSTOTAL_API_KEY"
```

### Konfigurasi API Keys

Untuk fungsi-fungsi tertentu, Anda mungkin perlu mendaftar dan mendapatkan kunci API dari:
- [Shodan](https://account.shodan.io/)
- [Censys](https://censys.io/)
- [VirusTotal](https://www.virustotal.com/)

Masukkan kunci API Anda ke dalam file `config.yaml` di bagian `api_keys`.

## Penggunaan Dasar

### Melihat Bantuan Umum
```bash
python main.py --help
```

### Melihat Modul yang Tersedia
```bash
python main.py modules
```

### Informasi Detail tentang Modul
```bash
python main.py modules -m dns_info
```

### Menjalankan Pemindaian dengan Modul Tertentu
```bash
python main.py scan -m dns_info -m server_info example.com
```

### Menjalankan Semua Modul
```bash
python main.py scan -a example.com
```

### Opsi Output
```bash
python main.py scan -m dns_info -o results.json example.com
```

### Format Output
```bash
python main.py scan -m dns_info -f csv -o results.csv example.com
```

### Menghasilkan Laporan HTML dari Hasil JSON
```bash
python main.py report results.json -o report.html
```

### Pemindaian Rekursif
```bash
python main.py scan -r -d 2 -m subdomain_enum example.com
```

### Menggunakan Proxy
```bash
python main.py scan -p http://user:pass@host:port -m server_info example.com
```

### Output Verbose
```bash
python main.py scan -v -m dns_info example.com
```

## Penggunaan Modul

LUINT memiliki enam modul utama:

### 1. Modul DNS Info
Mengumpulkan informasi DNS lengkap dari domain target:

```bash
python main.py scan -m dns_info example.com
```

Fitur utama:
- Resolusi DNS lengkap (A, AAAA, MX, NS, TXT, dll.)
- Lookup DNS Terbalik
- Lookup WHOIS
- Validasi DNSSEC
- Analisis catatan SPF, DMARC, dan DKIM
- Penilaian postur keamanan DNS dengan grading (A-F)
- Deteksi dan analisis dukungan DNS over HTTPS/TLS

### 2. Modul Server Info
Menganalisis infrastruktur server target:

```bash
python main.py scan -m server_info example.com
```

Fitur utama:
- Geolokasi IP
- Informasi ASN
- Analisis header HTTP/HTTPS
- Analisis sertifikat SSL/TLS
- Pemindaian port dengan deteksi layanan
- Deteksi teknologi web
- Penilaian postur keamanan infrastruktur dengan grading (A-F)
- Analisis risiko eksposur port

### 3. Modul Enumerasi Subdomain
Menemukan subdomain yang terkait dengan domain target:

```bash
python main.py scan -m subdomain_enum example.com
```

Fitur utama:
- Brute force subdomain
- Pemindaian permutasi
- Penemuan subdomain pasif
- Analisis log transparansi sertifikat
- Deteksi host virtual

### 4. Modul Penemuan Konten
Menemukan file dan direktori tersembunyi:

```bash
python main.py scan -m content_discovery example.com
```

Fitur utama:
- Penemuan file & direktori sensitif
- Ekstraksi metadata
- Brute forcing direktori
- Web crawling dengan ekstraksi link

### 5. Modul Analisis Email
Mengumpulkan informasi terkait email:

```bash
python main.py scan -m email_recon example.com
```

Fitur utama:
- Pengumpulan email dari halaman web
- Analisis catatan SPF, DKIM, dan DMARC
- Informasi kontak WHOIS
- Deteksi pola format email

### 6. Modul Pemeriksaan Keamanan
Mengevaluasi postur keamanan keseluruhan dari target:

```bash
python main.py scan -m security_checks example.com
```

Fitur utama:
- Pemeriksaan daftar hitam IP/domain
- Analisis header respons keamanan
- Pemindaian kerentanan berdasarkan informasi versi
- Deteksi konfigurasi yang salah

## Output dan Pelaporan

LUINT mendukung beberapa format output:

### Format JSON (Default)
```bash
python main.py scan -m dns_info -o results.json example.com
```

### Format CSV
```bash
python main.py scan -m dns_info -f csv -o results.csv example.com
```

### Format TXT
```bash
python main.py scan -m dns_info -f txt -o results.txt example.com
```

### Laporan HTML
Untuk menghasilkan laporan HTML yang lebih mudah dibaca:
```bash
python main.py report results.json -o report.html
```

## Pemecahan Masalah

### Masalah Umum

#### 1. Kesalahan modul tidak ditemukan
Pastikan Anda berada di direktori root proyek saat menjalankan perintah. Jika masalah berlanjut, coba instal ulang dependensi.

#### 2. Kesalahan waktu tunggu
Beberapa target mungkin membatasi permintaan. Coba gunakan proxy atau kurangi jumlah thread:
```bash
python main.py scan -m server_info --threads 5 example.com
```

#### 3. Keterbatasan API
Jika Anda mencapai batas API, pertimbangkan untuk mendapatkan kunci API dengan batas yang lebih tinggi atau tambahkan penundaan dengan menetapkan parameter rate limit yang lebih konservatif di `config.yaml`.

#### 4. Cache
Jika Anda mendapatkan hasil yang tidak diperbarui, coba nonaktifkan cache:
```bash
python main.py scan --no-cache -m dns_info example.com
```

#### 5. Mengaktifkan mode verbose
Untuk memecahkan masalah, gunakan flag verbose untuk melihat informasi debug:
```bash
python main.py scan -v -m dns_info example.com
```

---

Untuk informasi lebih lanjut dan pembaruan, kunjungi: [GitHub repository](https://github.com/pixelbrow720/luint)
