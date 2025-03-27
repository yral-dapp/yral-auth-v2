#!/bin/sh

# change this to your client id
CLIENT_ID=31122c67-4801-4e70-82f0-08e12daa4f2d

CLIENT_ID=$CLIENT_ID cargo run --release --bin jwt-secret-gen --features ssr