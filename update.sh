git pull
./scripts/feeds update -a
./scripts/feeds install -a
make defconfig
make download -j32
