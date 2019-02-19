Rust library for looking up IP (v4 only) address for matching ASN information containing:
* network base IP address and mask (u32 number in host byte order and number of bits of netmask or `ipnet::Ipv4Net` value),
* assinged AS number (e.g. 13335),
* owner country code (e.g. "US"),
* owner information (e.g. "CLOUDFLARENET - Cloudflare, Inc.").

This crate requires data file `ip2asn-v4.tsv` from [IPtoASN](https://iptoasn.com/).

# Usage

```rust
use asn_db::Db;
use std::fs::File;
use std::io::BufReader;

let db = Db::form_tsv(BufReader::new(File::open("ip2asn-v4.tsv").unwrap())).unwrap();
let record = db.lookup("1.1.1.1".parse().unwrap()).unwrap();

println!("{:#?}", record);
println!("{:#?}", record.network());
```

This prints:
```noformat
Record {
    ip: 16843008,
    prefix_len: 24,
    as_number: 13335,
    country: "US",
    owner: "CLOUDFLARENET - Cloudflare, Inc."
}
1.1.1.0/24
```