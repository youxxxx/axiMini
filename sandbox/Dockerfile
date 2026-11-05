# axiMini sandbox image (log 16).
#   docker build -t axi-sandbox:1 -f sandbox/Dockerfile samples/simulated
#
# Stage 1 compiles the harmless simulated samples as STATIC binaries (musl): no dynamic loader,
# no libc lookups, so their strace output shows only what the program itself does.
# Stage 2 is the runtime: Alpine + strace and nothing else (no compiler, no shell tools beyond
# busybox, no package manager use at runtime). Pin the base tag; for production pin the digest.

FROM alpine:3.20 AS build
RUN apk add --no-cache build-base
WORKDIR /src
COPY *.c ./
RUN mkdir /out && for f in *.c; do \
      gcc -O2 -static -s -Wall -o "/out/${f%.c}" "$f" || exit 1; \
    done

FROM alpine:3.20
RUN apk add --no-cache strace \
 && adduser -D -H -u 10001 sandbox
COPY --from=build /out/ /samples/
# Default user; the runner also passes --user explicitly.
USER 10001:10001
WORKDIR /work
