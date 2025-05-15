# Fitur Penilaian Postur Keamanan LUINT

Dokumen ini menjelaskan secara detail fitur penilaian postur keamanan yang tersedia di LUINT, yang mencakup komponen penilaian, sistem penilaian, dan rekomendasi.

## Daftar Isi
1. [Gambaran Umum](#gambaran-umum)
2. [Penilaian Keamanan DNS](#penilaian-keamanan-dns)
3. [Penilaian Keamanan Infrastruktur](#penilaian-keamanan-infrastruktur)
4. [Sistem Penilaian dan Peringkat](#sistem-penilaian-dan-peringkat)
5. [Rekomendasi Keamanan](#rekomendasi-keamanan)
6. [Contoh Penggunaan](#contoh-penggunaan)

## Gambaran Umum

LUINT menyediakan penilaian postur keamanan komprehensif untuk dua domain utama:
1. **Keamanan DNS**: Menilai konfigurasi DNS dan keamanan catatan DNS
2. **Keamanan Infrastruktur**: Menilai keamanan server, port, SSL/TLS, dan konfigurasi HTTP

Kedua penilaian ini memberikan:
- Skor keamanan keseluruhan (0-100)
- Peringkat berdasarkan huruf (A-F)
- Isu keamanan yang dikategorikan berdasarkan tingkat keparahan (kritis, tinggi, sedang, rendah)
- Rekomendasi spesifik untuk perbaikan
- Analisis komponen-per-komponen

## Penilaian Keamanan DNS

### Cara Menggunakan
```bash
python main.py scan -m dns_info example.com
```

### Komponen yang Dinilai

#### 1. Konfigurasi Catatan DNS
- **Konfigurasi SPF**: Keberadaan, sintaks, dan kekuatan catatan SPF
- **Konfigurasi DMARC**: Keberadaan, kebijakan, dan kelengkapan DMARC
- **Konfigurasi DKIM**: Keberadaan dan konfigurasi kunci DKIM
- **Konfigurasi CAA**: Keberadaan dan konfigurasi catatan CAA
- **Konfigurasi MX**: Keamanan server mail dan prioritas
- **Konfigurasi NS**: Redundansi dan penyebaran server nama

#### 2. Dukungan Keamanan DNS Modern
- **DNSSEC**: Implementasi, validasi, dan integritas
- **DNS over HTTPS (DoH)**: Dukungan dan konfigurasi
- **DNS over TLS (DoT)**: Dukungan dan konfigurasi

#### 3. Misconfigurations dan Kerentanan
- **Potensi Zone Transfer**: Deteksi kerentanan AXFR
- **Wildcard DNS**: Implikasi keamanan dari catatan wildcard
- **TTL Settings**: Pengaturan TTL terlalu pendek atau terlalu panjang
- **Catatan Usang/Tidak Digunakan**: Deteksi catatan yang tidak digunakan
- **Keterbukaan Informasi**: Penilaian kebocoran informasi melalui DNS

### Contoh Output Penilaian DNS
```json
{
  "security_posture": {
    "target": "example.com",
    "security_score": 78,
    "max_score": 100,
    "grade": "C",
    "security_issues": {
      "critical": [
        "Tidak ada implementasi DNSSEC"
      ],
      "high": [
        "Kebijakan DMARC tidak diatur ke 'reject'"
      ],
      "medium": [
        "Catatan SPF terlalu permisif",
        "Tidak ada catatan CAA"
      ],
      "low": [
        "TTL rendah pada catatan MX"
      ]
    },
    "recommendations": [
      "Implementasikan DNSSEC untuk validasi integritas DNS",
      "Tingkatkan kebijakan DMARC ke 'reject' untuk perlindungan spoofing maksimal",
      "Batasi catatan SPF ke server mail yang sah"
    ],
    "passed_checks": [
      "Konfigurasi server nama yang baik dengan redundansi",
      "Kebijakan DMARC termasuk pelaporan"
    ],
    "component_scores": {
      "spf_config": 15,
      "dmarc_config": 10,
      "dkim_config": 0,
      "dnssec": 0,
      "caa_records": 0,
      "nameserver_config": 20,
      "mx_security": 15,
      "privacy_protection": 18
    }
  }
}
```

## Penilaian Keamanan Infrastruktur

### Cara Menggunakan
```bash
python main.py scan -m server_info example.com
```

### Komponen yang Dinilai

#### 1. Eksposur Port dan Layanan
- **Port Berisiko Tinggi**: Port sensitif yang terbuka secara publik
- **Layanan yang Terdeteksi**: Jenis dan versi layanan yang berjalan
- **Port Tidak Biasa**: Port tinggi yang tidak standar dengan layanan aktif
- **Layanan Database**: Layanan database yang terekspos secara publik

#### 2. Konfigurasi SSL/TLS
- **Validasi Sertifikat**: Validitas, tanggal kedaluwarsa, dan integritas sertifikat
- **Panjang Kunci**: Kekuatan kriptografis kunci
- **Algoritma Tanda Tangan**: Kekuatan algoritma tanda tangan
- **Versi Protokol**: Dukungan untuk protokol aman modern
- **Cipher Suite**: Kekuatan dan keamanan suite sandi
- **Perfect Forward Secrecy**: Dukungan dan implementasi PFS
- **OCSP Stapling**: Dukungan dan implementasi

#### 3. Keamanan HTTP
- **Header Keamanan**: Keberadaan dan konfigurasi header keamanan kritis
- **Konfigurasi Content-Security-Policy**: Kekuatan dan kelengkapan CSP
- **Konfigurasi HSTS**: Keberadaan, umur maksimum, dan kelengkapan
- **Keamanan Cookie**: Flag Secure, HttpOnly, dan SameSite

#### 4. Deteksi Firewall dan CDN
- **Deteksi WAF**: Keberadaan dan jenis Web Application Firewall
- **Deteksi CDN**: Keberadaan dan konfigurasi Content Delivery Network
- **Konfigurasi Keamanan Cloud**: Fitur keamanan khusus penyedia cloud

#### 5. Pemindaian Kerentanan Port
- **Pemindaian Berbasis Versi**: Kerentanan berdasarkan informasi versi layanan
- **Pemindaian Kerentanan Lanjutan**: Deteksi kerentanan menggunakan script nmap
- **Identifikasi CVE**: Pengidentifikasian kerentanan yang diketahui

### Contoh Output Penilaian Infrastruktur
```json
{
  "security_posture": {
    "target": "example.com",
    "security_score": 65,
    "max_score": 100,
    "grade": "D",
    "security_issues": {
      "critical": [
        "Port SSH (22) terbuka dengan akses publik",
        "Protokol SSL usang (SSLv3) didukung"
      ],
      "high": [
        "Port database MySQL (3306) terbuka secara publik",
        "Header keamanan Content-Security-Policy hilang"
      ],
      "medium": [
        "Sertifikat SSL kedaluwarsa dalam 45 hari",
        "Cookie tidak menggunakan flag 'SameSite'"
      ],
      "low": [
        "Header Referrer-Policy hilang"
      ]
    },
    "recommendations": [
      "Batasi akses ke port SSH (22) hanya ke alamat IP tepercaya",
      "Nonaktifkan SSLv3 untuk mencegah serangan POODLE",
      "Batasi akses port database (3306) ke jaringan internal saja",
      "Implementasikan header Content-Security-Policy untuk mencegah XSS"
    ],
    "passed_checks": [
      "TLSv1.2 didukung",
      "Sertifikat SSL valid",
      "Panjang kunci SSL memadai (2048 bit)"
    ],
    "component_scores": {
      "ports_services": 5,
      "ssl_tls": 13,
      "http_security": 8,
      "firewall": 20,
      "cloud_security": 10,
      "version_vulnerabilities": 9
    }
  }
}
```

## Sistem Penilaian dan Peringkat

LUINT menggunakan sistem penilaian 0-100 dan peringkat berdasarkan huruf (A-F) untuk menilai keamanan keseluruhan:

| Peringkat | Rentang Skor | Deskripsi |
|-----------|-------------|------------|
| A         | 90-100      | Postur keamanan sangat baik dengan sedikit atau tanpa isu keamanan |
| B         | 80-89       | Postur keamanan baik dengan beberapa perbaikan minor yang direkomendasikan |
| C         | 70-79       | Postur keamanan rata-rata dengan beberapa isu keamanan yang harus diperbaiki |
| D         | 60-69       | Postur keamanan di bawah rata-rata dengan banyak isu keamanan yang harus diperbaiki |
| F         | 0-59        | Postur keamanan buruk dengan isu keamanan kritis yang harus diperbaiki segera |

Skor keamanan dihitung berdasarkan beberapa faktor:
1. **Skor Komponen Dasar**: Setiap komponen dinilai pada skala sendiri dan berkontribusi pada skor keseluruhan
2. **Penalti Masalah Kritis**: Masalah kritis mengurangi skor keseluruhan secara signifikan
3. **Penalti Masalah Tinggi**: Masalah dengan keparahan tinggi mengurangi skor dalam jumlah sedang
4. **Penalti Masalah Sedang dan Rendah**: Masalah dengan keparahan lebih rendah mengurangi skor dalam jumlah kecil

## Rekomendasi Keamanan

LUINT menghasilkan rekomendasi keamanan yang dapat ditindaklanjuti berdasarkan isu yang terdeteksi:

1. **Rekomendasi Prioritas**: Didasarkan pada isu kritis dan tinggi yang terdeteksi
2. **Rekomendasi Spesifik**: Disesuaikan dengan isu keamanan yang ditemukan
3. **Rekomendasi Praktis**: Memberikan langkah-langkah yang dapat ditindaklanjuti
4. **Rekomendasi Berbasis Industri**: Sesuai dengan praktik terbaik industri

### Contoh Rekomendasi

#### Contoh Rekomendasi DNS
- "Implementasikan DNSSEC untuk memvalidasi integritas DNS Anda"
- "Atur kebijakan DMARC ke 'reject' untuk perlindungan maksimal terhadap spoofing"
- "Tambahkan catatan CAA untuk membatasi otoritas sertifikat yang dapat menerbitkan sertifikat untuk domain Anda"

#### Contoh Rekomendasi Infrastruktur
- "Batasi akses ke port database (MySQL 3306) ke jaringan internal saja"
- "Nonaktifkan protokol SSL/TLS usang (SSLv3, TLSv1.0) untuk mencegah serangan downgrade"
- "Implementasikan header HTTP security Content-Security-Policy dengan direktif 'default-src self'"
- "Tingkatkan umur maksimum HSTS ke 1 tahun (31536000 detik) dan tambahkan direktif 'includeSubDomains'"

## Contoh Penggunaan

### Penilaian Keamanan Lengkap
```bash
python main.py scan -m dns_info -m server_info -m security_checks example.com -o security_assessment.json
```

### Laporan HTML dari Hasil Penilaian
```bash
python main.py report security_assessment.json -o security_report.html
```

### Pemindaian Port Lanjutan dengan Deteksi Kerentanan
```bash
# Edit config.yaml terlebih dahulu untuk mengaktifkan pemindaian port lanjutan
# server_info.perform_advanced_port_scan: true

python main.py scan -m server_info example.com -o vulnerability_scan.json
```

### Rekomendasi Khusus Subdomain
```bash
python main.py scan -r -m dns_info -m server_info example.com
```

---

Fitur penilaian postur keamanan LUINT memberikan wawasan komprehensif tentang keamanan infrastruktur DNS dan server, memungkinkan pengguna untuk dengan cepat mengidentifikasi, memprioritaskan, dan menyelesaikan masalah keamanan.