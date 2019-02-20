/*!
Look up IP address for matching ASN record that contains:
* network base IP address and mask (e.g. `ipnet::Ipv4Net` value like 1.1.1.0/24),
* assigned AS number (e.g. 13335),
* owner country code (e.g. "US"),
* owner information (e.g. "CLOUDFLARENET - Cloudflare, Inc.").

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

# Usage
Use `Db::from_tsv(reader)` to load database from `ip2asn-v4.tsv` formatted file.
You can then use `db.store(writer)` to store prepared, binary encoded data for fast loading with `Db::load(reader)`.

Look up records with `db.lookup(ip)`.
*/
use bincode::{deserialize_from, serialize_into};
use error_context::*;
use serde_derive::{Deserialize, Serialize};
use std::error::Error;
use std::fmt;
use std::io;
use std::io::{Read, Write};
use ipnet::Ipv4Subnets;
pub use std::net::Ipv4Addr;
pub use ipnet::Ipv4Net;

const DATABASE_DATA_TAG: &[u8; 4] = b"ASDB";
const DATABASE_DATA_VERSION: &[u8; 4] = b"bin1";

/// Autonomous system number record
#[derive(Serialize, Deserialize, Debug)]
pub struct Record {
    /// Network base IP address (host byte order)
    pub ip: u32,
    /// Network mask prefix in number of bits, e.g. 24 for 255.255.255.0 mask
    pub prefix_len: u8,
    /// Assigned AS number
    pub as_number: u32,
    /// Country code of network owner
    pub country: String,
    /// Network owner information
    pub owner: String,
}

impl Record {
    /// Get `Ipv4Net` representation of the network address
    pub fn network(&self) -> Ipv4Net {
        Ipv4Net::new(self.ip.into(), self.prefix_len).expect("bad network")
    }
}

#[derive(Debug)]
pub enum TsvParseError {
    TsvError(csv::Error),
    AddrFieldParseError(std::net::AddrParseError, &'static str),
    IntFieldParseError(std::num::ParseIntError, &'static str),
}

impl fmt::Display for TsvParseError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            TsvParseError::TsvError(_) => write!(f, "TSV format error"),
            TsvParseError::AddrFieldParseError(_, context) => {
                write!(f, "error parsing IP address while {}", context)
            }
            TsvParseError::IntFieldParseError(_, context) => {
                write!(f, "error parsing integer while {}", context)
            }
        }
    }
}

impl Error for TsvParseError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            TsvParseError::TsvError(err) => Some(err),
            TsvParseError::AddrFieldParseError(err, _) => Some(err),
            TsvParseError::IntFieldParseError(err, _) => Some(err),
        }
    }
}

impl From<csv::Error> for TsvParseError {
    fn from(error: csv::Error) -> TsvParseError {
        TsvParseError::TsvError(error)
    }
}

impl From<ErrorContext<std::net::AddrParseError, &'static str>> for TsvParseError {
    fn from(ec: ErrorContext<std::net::AddrParseError, &'static str>) -> TsvParseError {
        TsvParseError::AddrFieldParseError(ec.error, ec.context)
    }
}

impl From<ErrorContext<std::num::ParseIntError, &'static str>> for TsvParseError {
    fn from(ec: ErrorContext<std::num::ParseIntError, &'static str>) -> TsvParseError {
        TsvParseError::IntFieldParseError(ec.error, ec.context)
    }
}

/// Reads ASN database TSV file (`ip2asn-v4.tsv` format) provided by [IPtoASN](https://iptoasn.com/) as iterator of `Record`s
pub fn read_asn_tsv<'d, R: io::Read>(
    data: &'d mut csv::Reader<R>,
) -> impl Iterator<Item = Result<Record, TsvParseError>> + 'd {
    data.records()
        .filter(|record| {
            if let Ok(record) = record {
                let owner = &record[4];
                !(owner == "Not routed" || owner == "None")
            } else {
                true
            }
        })
        .map(|record| record.map_err(Into::<TsvParseError>::into))
        .map(|record| {
            record.and_then(|record| {
                let range_start: Ipv4Addr = record[0]
                    .parse()
                    .wrap_error_while("parsing range_start IP")?;
                let range_end: Ipv4Addr =
                    record[1].parse().wrap_error_while("parsing range_end IP")?;
                let as_number: u32 = record[2].parse().wrap_error_while("parsing as_number")?;
                let country = record[3].to_owned();
                let owner = record[4].to_owned();
                Ok((range_start, range_end, as_number, country, owner))
            })
        })
        .map(|data| {
            data.map(|(range_start, range_end, as_number, country, owner)| {
                Ipv4Subnets::new(range_start, range_end, 8).map(move |net| Record {
                    ip: net.network().into(),
                    prefix_len: net.prefix_len(),
                    country: country.clone(),
                    as_number,
                    owner: owner.clone(),
                })
            })
        })
        .flat_map(|data| {
            let mut records = None;
            let mut errors = None;

            match data {
                Ok(data) => records = Some(data),
                Err(err) => errors = Some(TsvParseError::from(err)),
            }

            records
                .into_iter()
                .flatten()
                .map(Ok)
                .chain(errors.into_iter().map(Err))
        })
}

#[derive(Debug)]
pub enum DbError {
    TsvError(TsvParseError),
    DbDataError(&'static str),
    FileError(io::Error, &'static str),
    BincodeError(bincode::Error, &'static str),
}

impl fmt::Display for DbError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            DbError::TsvError(_) => write!(f, "error opening ASN DB from TSV file"),
            DbError::FileError(_, context) => {
                write!(f, "error opening ASN DB from file while {}", context)
            }
            DbError::BincodeError(_, context) => write!(
                f,
                "error (de)serializing ASN DB to bincode format while {}",
                context
            ),
            DbError::DbDataError(message) => write!(f, "error while reading database: {}", message),
        }
    }
}

impl Error for DbError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            DbError::TsvError(err) => Some(err),
            DbError::FileError(err, _) => Some(err),
            DbError::BincodeError(err, _) => Some(err),
            DbError::DbDataError(_) => None,
        }
    }
}

impl From<TsvParseError> for DbError {
    fn from(err: TsvParseError) -> DbError {
        DbError::TsvError(err)
    }
}

impl From<ErrorContext<io::Error, &'static str>> for DbError {
    fn from(err: ErrorContext<io::Error, &'static str>) -> DbError {
        DbError::FileError(err.error, err.context)
    }
}

impl From<ErrorContext<bincode::Error, &'static str>> for DbError {
    fn from(err: ErrorContext<bincode::Error, &'static str>) -> DbError {
        DbError::BincodeError(err.error, err.context)
    }
}

//TODO: use eytzinger layout - requires non exact search support
//TODO: support for mmap'ed files to reduce memory usage?
//TODO: IPv6 support
/// Loaded ASN database that is optimized for looking up ASN by IP address
pub struct Db(Vec<Record>);

impl fmt::Debug for Db {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "asn_db::Db[total records: {}]", self.0.len())
    }
}

impl Db {
    /// Load database from TSV file as provided by [IPtoASN](https://iptoasn.com/) - only `ip2asn-v4.tsv` file format is supported a the moment
    pub fn form_tsv(data: impl Read) -> Result<Db, DbError> {
        let mut rdr = csv::ReaderBuilder::new()
            .delimiter(b'\t')
            .has_headers(false)
            .from_reader(data);
        let mut records = read_asn_tsv(&mut rdr).collect::<Result<Vec<_>, _>>()?;
        records.sort_by_key(|record| record.ip);
        Ok(Db(records))
    }

    /// Load previously stored database - this method is much faster than loading TSV file
    pub fn load(mut db_data: impl Read) -> Result<Db, DbError> {
        let mut tag = [0; 4];
        db_data.read_exact(&mut tag).wrap_error_while("reading database tag")?;
        if &tag != DATABASE_DATA_TAG {
            return Err(DbError::DbDataError("bad database data tag"))
        }

        let mut version = [0; 4];
        db_data.read_exact(&mut version).wrap_error_while("reading database version")?;
        if &version != DATABASE_DATA_VERSION {
            return Err(DbError::DbDataError("unsuported database version"))
        }

        let records: Vec<Record> = deserialize_from(db_data)
            .wrap_error_while("reading bincode DB file")?;

        Ok(Db(records))
    }

    /// Store database as binary data
    pub fn store(&self, mut db_data: impl Write) -> Result<(), DbError> {
        db_data.write(DATABASE_DATA_TAG).wrap_error_while("error writing tag")?;
        db_data.write(DATABASE_DATA_VERSION).wrap_error_while("error writing version")?;
        serialize_into(db_data, &self.0).wrap_error_while("stroing DB")?;
        Ok(())
    }

    /// Lookup ASN information by IP address where given IP belongs to AS network
    pub fn lookup(&self, ip: Ipv4Addr) -> Option<&Record> {
        match self.0.binary_search_by_key(&ip.into(), |record| record.ip) {
            Ok(index) => return Some(&self.0[index]), // IP was network base IP
            Err(index) => { // upper bound/insert index
                if index != 0 {
                    let record = &self.0[index - 1];
                    if record.network().contains(&ip) {
                        return Some(record);
                    }
                }
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;
    use std::io::{BufReader, BufWriter};
    use tempfile::tempdir;

    #[test]
    fn test_db() {
        let db = Db::form_tsv(BufReader::new(File::open("ip2asn-v4.tsv").unwrap())).unwrap();

        assert!(db
            .lookup("1.1.1.1".parse().unwrap())
            .unwrap()
            .owner
            .contains("CLOUDFLARENET"));
        assert!(db
            .lookup("8.8.8.8".parse().unwrap())
            .unwrap()
            .owner
            .contains("GOOGLE"));
        assert!(db
            .lookup("8.8.4.4".parse().unwrap())
            .unwrap()
            .owner
            .contains("GOOGLE"));

        let temp_dir = tempdir().unwrap();
        let db_file = temp_dir.path().join("asn-db.dat");

        db.store(BufWriter::new(File::create(&db_file).unwrap())).unwrap();

        let db = Db::load(BufReader::new(File::open(&db_file).unwrap())).unwrap();

        drop(db_file);
        drop(temp_dir);

        assert!(db
            .lookup("1.1.1.1".parse().unwrap())
            .unwrap()
            .owner
            .contains("CLOUDFLARENET"));
        assert!(db
            .lookup("8.8.8.8".parse().unwrap())
            .unwrap()
            .owner
            .contains("GOOGLE"));
        assert!(db
            .lookup("8.8.4.4".parse().unwrap())
            .unwrap()
            .owner
            .contains("GOOGLE"));
    }
}
