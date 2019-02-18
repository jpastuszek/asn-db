use serde_derive::{Serialize, Deserialize};
use error_context::*;
use ipnet::*;
use std::net::Ipv4Addr;
use std::io;
use std::fmt;
use std::error::Error;
use std::io::{BufReader, BufWriter};
use std::fs::File;
use std::path::Path;
use superslice::Ext;
use bincode::{serialize_into, deserialize_from};

#[derive(Serialize, Deserialize, Debug)]
pub struct AsnRecord {
    pub ip: u32,
    pub prefix_len: u8,
    pub country: String,
    pub as_number: u32, 
    pub owner: String,
}

impl AsnRecord {
    pub fn network(&self) -> Ipv4Net {
        Ipv4Net::new(self.ip.into(), self.prefix_len).expect("Bad network")
    }
}

#[derive(Debug)]
pub enum AsnTsvParseError {
    TsvError(csv::Error),
    AddrFieldParseError(std::net::AddrParseError, &'static str),
    IntFieldParseError(std::num::ParseIntError, &'static str),
}

impl fmt::Display for AsnTsvParseError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            AsnTsvParseError::TsvError(_) => write!(f, "TSV format error"),
            AsnTsvParseError::AddrFieldParseError(_, context) => write!(f, "error parsing IP address while {}", context),
            AsnTsvParseError::IntFieldParseError(_, context) => write!(f, "error parsing integer while {}", context),
        }
    }
}

impl Error for AsnTsvParseError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            AsnTsvParseError::TsvError(err) => Some(err),
            AsnTsvParseError::AddrFieldParseError(err, _) => Some(err),
            AsnTsvParseError::IntFieldParseError(err, _) => Some(err),
        }
    }
}

impl From<csv::Error> for AsnTsvParseError {
    fn from(error: csv::Error) -> AsnTsvParseError {
        AsnTsvParseError::TsvError(error)
    }
}

impl From<ErrorContext<std::net::AddrParseError, &'static str>> for AsnTsvParseError {
    fn from(ec: ErrorContext<std::net::AddrParseError, &'static str>) -> AsnTsvParseError {
        AsnTsvParseError::AddrFieldParseError(ec.error, ec.context)
    }
}


impl From<ErrorContext<std::num::ParseIntError, &'static str>> for AsnTsvParseError {
    fn from(ec: ErrorContext<std::num::ParseIntError, &'static str>) -> AsnTsvParseError {
        AsnTsvParseError::IntFieldParseError(ec.error, ec.context)
    }
}

/// Reads ASN database TSV file as provided at https://iptoasn.com/
pub fn read_asn_tsv<'d, R: io::Read>(data: &'d mut csv::Reader<R>) -> impl Iterator<Item=Result<AsnRecord, AsnTsvParseError>> + 'd {
    data.records()
        .filter(|record| {
            if let Ok(record) = record {
                let owner = &record[4];
                !(owner == "Not routed" || owner == "None")
            } else {
                true
            }
        })
        .map(|record| record.map_err(Into::<AsnTsvParseError>::into))
        .map(|record| {
            record.and_then(|record| {
                let range_start: Ipv4Addr = record[0].parse().wrap_error_while("parsing range_start IP")?;
                let range_end: Ipv4Addr = record[1].parse().wrap_error_while("parsing range_end IP")?;
                let as_number: u32 = record[2].parse().wrap_error_while("parsing as_number")?;
                let country = record[3].to_owned();
                let owner = record[4].to_owned();
                Ok((range_start, range_end, as_number, country, owner))
            })
        })
        .map(|data| {
            data.map(|(range_start, range_end, as_number, country, owner)| {
                Ipv4Subnets::new(range_start, range_end, 8).map(move |net| {
                    AsnRecord {
                        ip: net.network().into(),
                        prefix_len: net.prefix_len(),
                        country: country.clone(),
                        as_number,
                        owner: owner.clone(),
                    }
                })
            })
        })
        .flat_map(|data| {
            let mut records = None;
            let mut errors = None;

            match data {
                Ok(data) => records = Some(data),
                Err(err) => errors = Some(AsnTsvParseError::from(err)),
            }

            records.into_iter().flatten().map(Ok).chain(errors.into_iter().map(Err))
        })
}

pub struct AsnDb(Vec<AsnRecord>);

#[derive(Debug)]
pub enum AsnDbError {
    TsvError(AsnTsvParseError),
    FileError(io::Error, &'static str),
    BincodeError(bincode::Error, &'static str),
}

impl fmt::Display for AsnDbError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            AsnDbError::TsvError(_) => write!(f, "error opening ASN DB from TSV file"),
            AsnDbError::FileError(_, context) => write!(f, "error opening ASN DB from file while {}", context),
            AsnDbError::BincodeError(_, context) => write!(f, "error (de)serializing ASN DB to bincode format while {}", context),
        }
    }
}

impl Error for AsnDbError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            AsnDbError::TsvError(err) => Some(err),
            AsnDbError::FileError(err, _) => Some(err),
            AsnDbError::BincodeError(err, _) => Some(err),
        }
    }
}

impl From<AsnTsvParseError> for AsnDbError {
    fn from(err: AsnTsvParseError) -> AsnDbError {
        AsnDbError::TsvError(err)
    }
}

impl From<ErrorContext<io::Error, &'static str>> for AsnDbError {
    fn from(err: ErrorContext<io::Error, &'static str>) -> AsnDbError {
        AsnDbError::FileError(err.error, err.context)
    }
}

impl From<ErrorContext<bincode::Error, &'static str>> for AsnDbError {
    fn from(err: ErrorContext<bincode::Error, &'static str>) -> AsnDbError {
        AsnDbError::BincodeError(err.error, err.context)
    }
}

impl AsnDb {
    pub fn form_tsv_file(path: impl AsRef<Path>) -> Result<AsnDb, AsnDbError> {
        let mut rdr = csv::ReaderBuilder::new().delimiter(b'\t').from_reader(BufReader::new(File::open(path).wrap_error_while("opending TSV file")?));
        let mut records = read_asn_tsv(&mut rdr).collect::<Result<Vec<_>, _>>()?;
        records.sort_by_key(|record| record.ip);
        Ok(AsnDb(records))
    }

    pub fn from_stored_file(path: impl AsRef<Path>) -> Result<AsnDb, AsnDbError> {
        let db_file = File::open(&path).wrap_error_while("opening stored ASN DB file")?;
        Ok(AsnDb(deserialize_from(BufReader::new(db_file)).wrap_error_while("reading bincode DB file")?))
    }

    pub fn lookup(&self, ip: Ipv4Addr) -> Option<&AsnRecord> {
        let index = self.0.upper_bound_by_key(&ip.into(), |record| record.ip);
        if index != 0 {
            let record = &self.0[index - 1];
            if record.network().contains(&ip) {
                return Some(record)
            }
        }
        None
    }

    pub fn store(&self, path: impl AsRef<Path>) -> Result<(), AsnDbError> {
        let path = path.as_ref();
        let db_file = File::create(&path).wrap_error_while("creating ASN DB file for storage")?;
        serialize_into(BufWriter::new(db_file), &self.0).wrap_error_while("stroing DB")?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lookup() {
        let db = AsnDb::from_stored_file("db.bincode").unwrap();
        assert!(db.lookup("1.1.1.1".parse().unwrap()).unwrap().owner.contains("CLOUDFLARENET"));
        assert!(db.lookup("8.8.8.8".parse().unwrap()).unwrap().owner.contains("GOOGLE"));
        assert!(db.lookup("8.8.4.4".parse().unwrap()).unwrap().owner.contains("GOOGLE"));
    }
}