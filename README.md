# Vishv (personal movie site)
1. Install Python 3.9+
2. In this folder:  pip install -r requirements.txt
3. Run:             python app.py
4. Open:            http://127.0.0.1:5050

Your keys live in .env (server side only). Your watchlist, ratings and reviews
are saved in vishv.db next to app.py. Back that file up to keep your data.

## Running with HTTPS (removes the "not secure" warning)

Browsers only show the padlock for HTTPS with a certificate they trust. A plain
self-signed certificate encrypts the traffic but the browser still warns, so use
mkcert, which makes a certificate your own devices trust.

1. Install mkcert (https://github.com/FiloSottile/mkcert), then run once:
       mkcert -install
2. In this folder, make a certificate for the address you open the site on:
       mkcert 10.118.107.175 localhost 127.0.0.1
   This creates two .pem files (note their names).
3. Add to .env (use your real file names):
       SSL_CERT=10.118.107.175+2.pem
       SSL_KEY=10.118.107.175+2-key.pem
4. Run python app.py and open https://10.118.107.175:5050

Other devices (your friend's phone or laptop) must trust the mkcert root
certificate too: copy rootCA.pem (folder shown by `mkcert -CAROOT`) to that
device and install it as a trusted certificate. If your network address changes,
make a new certificate for the new address.

Never share or commit the key (.pem) files. Add *.pem to .gitignore.
