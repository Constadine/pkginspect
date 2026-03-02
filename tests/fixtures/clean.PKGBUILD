# Maintainer: John Doe <john@example.com>
pkgname=clean-pkg
pkgver=1.0
pkgrel=1
pkgdesc="A clean, well-maintained package"
arch=(x86_64)
url="https://example.com"
license=(MIT)
depends=(glibc)
source=("https://example.com/clean-pkg-${pkgver}.tar.gz")
sha512sums=('abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890')

build() {
    make
}

package() {
    make DESTDIR="$pkgdir" install
}
