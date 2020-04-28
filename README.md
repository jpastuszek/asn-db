[![Latest Version]][crates.io] [![Documentation]][docs.rs] ![License]

`asn-db` is a Rust library that can load and index [ASN] database (`ip2asn-v4.tsv` file) from [IPtoASN] website.

Once loaded it can be used to lookup an IP address for matching [ASN] record that contains:

* network base IP address and mask (e.g. [ipnet::Ipv4Net](https://docs.rs/ipnet/2.3.0/ipnet/struct.Ipv4Net.html) value like `1.1.1.0/24`),
* assigned AS number (e.g. `13335`),
* owner country code (e.g. `US`),
* owner information (e.g. `CLOUDFLARENET - Cloudflare, Inc.`).

It is also possible to write and then read optimized binary representation of the database to a file for fast load times.
Note that at this time only IPv4 records are supported.

# Example

Load database from `ip2asn-v4.tsv` file and lookup `1.1.1.1` IP address.

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

[ASN]: https://en.wikipedia.org/wiki/Autonomous_system_%28Internet%29#Assignment
[IPtoASN]: https://iptoasn.com/
[crates.io]: https://crates.io/crates/asn-db
[Latest Version]: https://img.shields.io/crates/v/asn-db.svg
[Documentation]: https://docs.rs/asn-db/badge.svg
[docs.rs]: https://docs.rs/asn-db
[License]: https://img.shields.io/crates/l/asn-db.svg
