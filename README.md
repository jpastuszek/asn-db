This Rust library can be used to look up IP address for matching ASN record that contains:
* network base IP address and mask (e.g. `ipnet::Ipv4Net` value like 1.1.1.0/24),
* assigned AS number (e.g. 13335),
* owner country code (e.g. "US"),
* owner information (e.g. "CLOUDFLARENET - Cloudflare, Inc.").

This crate requires data file `ip2asn-v4.tsv` from [IPtoASN](https://iptoasn.com/) and only supports IP v4 addresses (PR for v6 is welcome).

# Example
Load database from `ip2asn-v4.tsv` file and look up `1.1.1.1` IP address.

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

Note that this library also provides methods of storing the database in binary format for quicker load times.

See documentation for details at [docs.rs](https://docs.rs/asn-db).