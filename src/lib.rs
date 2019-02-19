use bincode::{deserialize_from, serialize_into};
use error_context::*;
use ipnet::*;
use serde_derive::{Deserialize, Serialize};
use std::error::Error;
use std::fmt;
use std::fs::File;
use std::io;
use std::io::{BufReader, BufWriter};
use std::net::Ipv4Addr;
use std::path::Path;

//TODO: reorder fields?
#[derive(Serialize, Deserialize, Debug)]
pub struct Record {
    pub ip: u32,
    pub prefix_len: u8,
    pub country: String,
    pub as_number: u32,
    pub owner: String,
}

impl Record {
    pub fn network(&self) -> Ipv4Net {
        Ipv4Net::new(self.ip.into(), self.prefix_len).expect("Bad network")
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

/// Reads ASN database TSV file as provided at https://iptoasn.com/
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

// TODO: try loading ip vec separately for search
// TODO: use stdlib search?
// TODO: use eytzinger layout
pub struct Db(Vec<Record>);

#[derive(Debug)]
pub enum DbError {
    TsvError(TsvParseError),
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
        }
    }
}

impl Error for DbError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            DbError::TsvError(err) => Some(err),
            DbError::FileError(err, _) => Some(err),
            DbError::BincodeError(err, _) => Some(err),
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

//TODO: write data file and mmap it so we don't waste memory
impl Db {
    //TODO: Read and Write not paths
    pub fn form_tsv_file(path: impl AsRef<Path>) -> Result<Db, DbError> {
        let mut rdr = csv::ReaderBuilder::new()
            .delimiter(b'\t')
            .from_reader(BufReader::new(
                File::open(path).wrap_error_while("opending TSV file")?,
            ));
        let mut records = read_asn_tsv(&mut rdr).collect::<Result<Vec<_>, _>>()?;
        records.sort_by_key(|record| record.ip);
        Ok(Db(records))
    }

    pub fn from_stored_file(path: impl AsRef<Path>) -> Result<Db, DbError> {
        let db_file = File::open(&path).wrap_error_while("opening stored ASN DB file")?;
        let records: Vec<Record> = deserialize_from(BufReader::new(db_file))
            .wrap_error_while("reading bincode DB file")?;
        Ok(Db(records))
    }

    // TODO: write 4 byts ID "ASDB" + 4 byte version (for allignment)
    pub fn store(&self, path: impl AsRef<Path>) -> Result<(), DbError> {
        let path = path.as_ref();
        let db_file = File::create(&path).wrap_error_while("creating ASN DB file for storage")?;
        serialize_into(BufWriter::new(db_file), &self.0).wrap_error_while("stroing DB")?;
        Ok(())
    }

    pub fn lookup(&self, ip: Ipv4Addr) -> Option<&Record> {
        match self.0.binary_search_by_key(&ip.into(), |record| record.ip) {
            Ok(index) => return Some(&self.0[index]), // network IP
            Err(index) => {
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

    #[test]
    fn test_lookup() {
        let db = Db::from_stored_file("db.bincode").unwrap();
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
