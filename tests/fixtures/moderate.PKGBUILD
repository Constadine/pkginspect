# Maintainer: Jane Smith <jane@example.com>
pkgname=moderate-pkg
pkgver=2.3
pkgrel=1
pkgdesc="A package with some issues"
arch=(x86_64)
url="https://example.com"
license=(GPL2)
source=("http://example.com/moderate-pkg-${pkgver}.tar.gz"
        "git+https://github.com/example/repo")
sha256sums=('abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890'
            'SKIP')

build() {
    ./configure
    make
}

package() {
    make DESTDIR="$pkgdir" install
}
