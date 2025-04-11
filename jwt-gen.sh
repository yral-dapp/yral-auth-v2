#!/bin/sh

# change this to your client id
CLIENT_ID=6a0101eb-8496-4afb-ba48-425187c3a30d

CLIENT_ID=$CLIENT_ID cargo run --release --bin jwt-secret-gen --features ssr