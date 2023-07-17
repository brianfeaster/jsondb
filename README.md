# About JSONDB

HTTPS accessible JSON database with integrated RPN scripting.

# Quick Start

    RUST_LOG=info DBPORT=4441 JSONDB=MYDBFILE.json KEYPEM=MYPRIVKEY.pem CRTPEM=MYCERT.pem cargo run

# Examples

## Store
    curl https://MYWEBSITE.COM:4441/jsondb/v1/MY_DB_NAME --json '{"a":1,"b":2,"c":3}'
2

## Retrieve
    curl https://MYWEBSITE.COM:4441/jsondb/v1/MY_DB_NAME --json '["a","b"]
{"a":1,"b":2}

## REST GET
    curl https://MYWEBSITE.COM:4441/jsondb/v1/MY_DB_NAME/b
2

## Eval
    curl https://MYWEBSITE.COM:4441/jsondb/v1/MY_DB_NAME -d 'a b + c * 1000 +'
1009.0
