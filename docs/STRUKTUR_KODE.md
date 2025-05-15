# Struktur Kode LUINT

Dokumen ini menjelaskan struktur kode dan arsitektur proyek LUINT untuk memudahkan pengembangan dan pemeliharaan.

## Gambaran Umum

LUINT dibangun dengan filosofi modular, memisahkan fungsi-fungsi inti dan modul-modul plugin yang dapat dipertukarkan. Pendekatan ini memungkinkan ekstensi yang mudah dan mempertahankan prinsip tanggung jawab tunggal.

## Struktur Direktori Utama

```
luint/
├── core/              # Fungsi dan kelas inti
│   ├── __init__.py
│   ├── scanner.py     # Mesin pemindaian utama
│   └── plugin_manager.py  # Pengelola modul plugin
├── modules/           # Modul plugin OSINT
│   ├── __init__.py
│   ├── dns_info.py
│   ├── server_info.py
│   ├── subdomain_enum.py
│   ├── content_discovery.py
│   ├── email_recon.py
│   └── security_checks.py
├── utils/             # Utilitas dan alat pembantu
│   ├── __init__.py
│   ├── helpers.py     # Fungsi-fungsi pembantu umum
│   ├── logger.py      # Sistem logging
│   ├── cache.py       # Pengelola cache
│   └── rate_limiter.py  # Pembatas laju permintaan API
├── constants.py       # Konstanta global dan enumerasi
└── __init__.py

wordlists/            # Daftar kata untuk brute-forcing
├── subdomains.txt
├── directories.txt
└── files.txt

logs/                 # Direktori untuk log runtime

main.py               # Titik masuk dan antarmuka baris perintah (CLI)
config.yaml           # File konfigurasi
```

## Aliran Proses Utama

1. **Inisialisasi**: `main.py` memproses argumen baris perintah dan mengatur lingkungan.
2. **Pemuatan Plugin**: `plugin_manager.py` menemukan dan memuat modul plugin yang tersedia.
3. **Konfigurasi**: File `config.yaml` dibaca dan diproses.
4. **Eksekusi**: Pemindaian dijalankan melalui `scanner.py` yang mengkoordinasikan modul.
5. **Output**: Hasil dikumpulkan, diproses, dan disajikan dalam format yang ditentukan.

## Detail Komponen Utama

### Core

#### scanner.py
Mengimplementasikan mesin pemindaian inti yang mengelola proses pemindaian keseluruhan:
- Kelas `Scanner`: Orkestrator modul plugin
- Metode `run_scan()`: Menjalankan pemindaian dengan modul yang dipilih
- Metode `consolidate_results()`: Menggabungkan hasil dari modul yang berbeda

#### plugin_manager.py
Mengelola pencarian, pemuatan, dan konfigurasi modul plugin:
- Kelas `PluginManager`: Mengelola modul yang tersedia
- Metode `discover_modules()`: Menemukan modul plugin yang tersedia
- Metode `load_module()`: Memuat dan menginisialisasi modul plugin

### Modules

Setiap modul plugin OSINT mengimplementasikan struktur yang konsisten:

```python
class ModuleNameScanner:
    """
    Module description.
    Handles specific OSINT capabilities.
    """
    
    def __init__(self, target, config=None, cache_manager=None, rate_limiter=None, api_key_manager=None):
        """
        Initialize the scanner.
        
        Args:
            target (str): Target domain or IP
            config (dict, optional): Module configuration
            cache_manager: Cache manager instance
            rate_limiter: Rate limiter instance
            api_key_manager: API key manager instance
        """
        self.target = target
        self.config = config or {}
        self.cache_manager = cache_manager
        self.rate_limiter = rate_limiter
        self.api_key_manager = api_key_manager
        self.logger = get_logger()
        
    def scan(self) -> Dict[str, Any]:
        """
        Run the scan and return results.
        
        Returns:
            dict: Scan results
        """
        # Module-specific scanning logic
        return results
```

#### Modul DNS Info (dns_info.py)
Mengimplementasikan fungsi pemindaian DNS komprehensif:
- Pencarian DNS (A, AAAA, MX, NS, TXT, dll.)
- Lookup WHOIS
- Validasi DNSSEC
- Analisis SPF/DMARC/DKIM
- Penilaian postur keamanan DNS

#### Modul Server Info (server_info.py)
Menganalisis informasi infrastruktur server:
- Geolokasi IP dan informasi ASN
- Analisis header HTTP/HTTPS
- Pemeriksaan sertifikat SSL/TLS
- Pemindaian port dan deteksi layanan
- Deteksi teknologi web
- Penilaian postur keamanan infrastruktur

#### Modul Enumerasi Subdomain (subdomain_enum.py)
Mengimplementasikan metode penemuan subdomain:
- Brute-forcing subdomain
- Permutasi subdomain
- Pencarian berbasis sertifikat
- Analisis log transparansi sertifikat

#### Modul Penemuan Konten (content_discovery.py)
Mencari file dan direktori tersembunyi:
- Brute-forcing direktori
- Deteksi file sensitif
- Ekstraksi metadata
- Web crawling

#### Modul Recon Email (email_recon.py)
Mengumpulkan informasi terkait email:
- Pengumpulan email dari situs web
- Analisis catatan SPF/DKIM/DMARC
- Deteksi pola format email

#### Modul Pemeriksaan Keamanan (security_checks.py)
Menjalankan pemeriksaan keamanan berbagai:
- Validasi header keamanan
- Analisis konfigurasi
- Pengecekan daftar hitam IP/domain

### Utils

#### helpers.py
Menyediakan fungsi-fungsi pembantu umum:
- Resolusi DNS
- Pemformatan output
- Validasi input
- Normalisasi URL

#### logger.py
Mengimplementasikan sistem logging:
- Konfigurasi logger
- Format pesan
- Manajemen level log

#### cache.py
Mengelola sistem cache untuk mengoptimalkan kinerja:
- Kelas `CacheManager`: Mengelola penyimpanan cache
- Metode `get()`: Mengambil hasil dari cache
- Metode `set()`: Menyimpan hasil ke cache

#### rate_limiter.py
Mengimplementasikan pembatasan laju permintaan API:
- Kelas `RateLimiter`: Mengelola laju permintaan
- Metode `wait()`: Menerapkan jeda yang sesuai
- Metode `update()`: Memperbarui status laju permintaan

## CLI Interface

Main.py mengimplementasikan antarmuka baris perintah menggunakan library `click`:

```python
@click.group()
@click.version_option(version='1.0.0')
def cli():
    """
    LUINT - A comprehensive modular OSINT tool for network reconnaissance and security analysis.
    """
    pass

@cli.command()
@click.argument('target')
@click.option('-o', '--output', help='Output file path for results')
@click.option('-f', '--format', type=click.Choice(['json', 'csv', 'txt']), default='json', help='Output format')
@click.option('-m', '--module', multiple=True, help='Specify modules to run')
@click.option('-a', '--all', is_flag=True, help='Run all modules')
# ... more options ...
def scan(target, output, format, module, all, **kwargs):
    """Scan a target domain or IP"""
    # Scan logic implementation
    
@cli.command()
@click.option('-m', '--module', help='Show details for a specific module')
def modules(module):
    """List available modules"""
    # Module listing logic
    
# More commands...

if __name__ == '__main__':
    cli()
```

## Ekstensi dan Pengembangan

### Menambahkan Modul Baru

1. Buat file Python baru di direktori `luint/modules/`
2. Implementasikan kelas scanner dengan metode `scan()`
3. Tambahkan entri kategori di `luint/constants.py` jika diperlukan

### Menambahkan Command CLI Baru

1. Edit `main.py`
2. Tambahkan fungsi baru dengan dekorator `@cli.command()`
3. Implementasikan logika perintah

## Pengelolaan Dependensi

Dependensi proyek dikelola melalui `pyproject.toml`:

```toml
[build-system]
requires = ["setuptools>=42", "wheel"]
build-backend = "setuptools.build_meta"

[project]
name = "luint"
version = "1.0.0"
description = "Comprehensive modular OSINT tool"
readme = "README.md"
authors = [
    {name = "pixelbrow720", email = "pixelbrow13@gmail.com"}
]
requires-python = ">=3.8"
dependencies = [
    "click>=8.0.0",
    "requests>=2.25.0",
    "dnspython>=2.1.0",
    "python-whois>=0.7.3",
    # ... more dependencies ...
]
```

## Konvensi Kode

- Gaya Kode: Python PEP 8
- Dokumentasi: Docstrings dalam format Google
- Pengujian: Terletak di direktori `tests/` (jika ada)
- Penanganan Error: Menggunakan pembuatan dan penangkapan exception khusus
- Logging: Menggunakan modul `logging` Python dengan tingkat yang sesuai

---

Dokumen ini dirancang untuk memberikan gambaran umum tentang struktur kode LUINT. Untuk informasi lebih rinci tentang fungsi atau kelas tertentu, silakan merujuk ke dokumentasi dalam kode sumber.