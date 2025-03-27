#!/bin/sh

# change this to your client id
CLIENT_ID=8583a20d-c974-48f1-8277-0b68e49cf6d1

CLIENT_ID=$CLIENT_ID cargo run --release --bin jwt-secret-gen --features ssr