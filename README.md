# simontini-mockup

## Cloudflare Turnstile

Widget Subscribe menggunakan site key berikut:

```text
0x4AAAAAAEB2t5fz6Yb-YTz4
```

Secret key tidak boleh disimpan di HTML atau JavaScript. Sediakan secret pada
environment Apache/PHP lalu restart Apache:

```text
TURNSTILE_SECRET_KEY=secret-dari-dashboard-cloudflare
```

Endpoint `verify-turnstile.php` akan membaca environment tersebut dan
memverifikasi token melalui Cloudflare Siteverify. Pastikan hostname production
dan hostname development yang diperlukan sudah diizinkan pada konfigurasi
widget Cloudflare Turnstile.
