FROM ghcr.io/goreleaser/goreleaser-cross:v1.25.5

# Install zig toolchain at build time (not at release time).
# This image is built once, pushed to our GHCR, and pinned by tag.
ARG ZIG_VERSION=0.14.0
RUN curl -sSL "https://ziglang.org/download/${ZIG_VERSION}/zig-linux-x86_64-${ZIG_VERSION}.tar.xz" \
    -o /tmp/zig.tar.xz && \
    tar xJf /tmp/zig.tar.xz -C /usr/local && \
    ln -sf "/usr/local/zig-linux-x86_64-${ZIG_VERSION}/zig" /usr/local/bin/zig && \
    rm /tmp/zig.tar.xz && \
    zig version

# Install zig cc wrapper scripts targeting glibc 2.17
RUN printf '#!/bin/sh\nexec zig cc -target x86_64-linux-gnu.2.17 "$@"\n' > /usr/local/bin/zig-cc-x86_64 && \
    printf '#!/bin/sh\nexec zig cc -target aarch64-linux-gnu.2.17 "$@"\n' > /usr/local/bin/zig-cc-aarch64 && \
    printf '#!/bin/sh\nexec zig cc -target arm-linux-gnueabihf.2.17 "$@"\n' > /usr/local/bin/zig-cc-arm && \
    chmod +x /usr/local/bin/zig-cc-*
