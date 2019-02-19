use bincode::{deserialize_from, serialize_into};
use error_context::*;
use ipnet::*;
use serde_derive::{Deserialize, Serialize};
use std::error::Error;
use std::fmt;
use std::io;
use std::io::{Read, Write};
use std::net::Ipv4Addr;

const DATABASE_DATA_TAG: &[u8; 4] = b"ASDB";
const DATABASE_DATA_VERSION: &[u8; 4] = b"bin1";

#[derive(Serialize, Deserialize, Debug)]
pub struct Record {
    pub ip: u32,
    pub prefix_len: u8,
    pub as_number: u32,
    pub country: String,
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

//TODO: write data file and mmap it so we don't waste memory
impl Db {
    pub fn form_tsv_file(data: impl Read) -> Result<Db, DbError> {
        let mut rdr = csv::ReaderBuilder::new()
            .delimiter(b'\t')
            .from_reader(data);
        let mut records = read_asn_tsv(&mut rdr).collect::<Result<Vec<_>, _>>()?;
        records.sort_by_key(|record| record.ip);
        Ok(Db(records))
    }

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

    pub fn store(&self, mut db_data: impl Write) -> Result<(), DbError> {
        db_data.write(DATABASE_DATA_TAG).wrap_error_while("error writing tag")?;
        db_data.write(DATABASE_DATA_VERSION).wrap_error_while("error writing version")?;
        serialize_into(db_data, &self.0).wrap_error_while("stroing DB")?;
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
    use std::fs::File;
    use std::io::BufReader;

    #[test]
    fn test_lookup() {
        let db = Db::load(BufReader::new(File::open("db.bincode").unwrap())).unwrap();
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
