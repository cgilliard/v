//! What the wallet keeps: a few tables, each a run of bytes, in a file
//! of pages of its own ([`crate::store::PageFile`]).
//!
//! The wallet's records are small beside the chain's and change with
//! every payment, and what matters of them is that they change whole:
//! an output marked spent and the transaction that spends it are
//! written in one step, or neither is. So each table is kept as one
//! run of bytes ([`Blob`]), and a change writes the tables it touches
//! anew and then, when those are safely on disk, one root record that
//! names every table's place. A crash at any moment leaves the tables
//! as they were before the change, or as they are after it.
//!
//! What a table's bytes are is its owner's affair: this knows only how
//! many tables there are.
//!
//! ```text
//! root := "tabwlt" | format (1) | tables (1) | a blob's place (10), for each table
//! ```

use std::io;

use crate::store::blob::Blob;
use crate::store::{Backend, PageFile};

/// Tables a file holds, at the most: what fits its root record.
pub const TABLES: usize = 32;
/// As many as a file made before there were so many has: such a file
/// is opened, its other tables empty, and written with all of them.
const TABLES_BEFORE: usize = 16;

const MAGIC: &[u8; 6] = b"tabwlt";
/// How the root record is laid out.
const FORMAT: u8 = 1;

fn corrupt(what: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, what)
}

/// A wallet's file, open.
pub struct Records<B: Backend> {
    file: PageFile<B>,
    tables: [Option<Blob>; TABLES],
}

impl<B: Backend> Records<B> {
    /// Opens the file of `backend`, making it if there is none: with
    /// every table empty.
    pub fn open(backend: B) -> io::Result<Records<B>> {
        let file = PageFile::open_or_create(backend)?;
        let mut tables = [None; TABLES];
        let root = file.root();
        let payload = root.payload();
        if !payload.is_empty() {
            if payload.len() < 8 || &payload[..6] != MAGIC || payload[6] != FORMAT {
                return Err(corrupt("not a wallet's file, or one of a format not known here"));
            }
            let held = payload[7] as usize;
            if ![TABLES, TABLES_BEFORE].contains(&held) || payload.len() != 8 + held * Blob::BYTES {
                return Err(corrupt("a wallet's file of another number of tables"));
            }
            for (table, place) in tables.iter_mut().zip(payload[8..].chunks_exact(Blob::BYTES)) {
                *table = Blob::get_option(place)?;
            }
        }
        // What the root reaches is in use, and nothing else is.
        if !file.is_sealed() {
            for blob in tables.iter().flatten() {
                blob.mark(&file)?;
            }
            file.seal();
        }
        Ok(Records { file, tables })
    }

    /// What the file is kept in.
    pub fn backend(&self) -> &B {
        self.file.backend()
    }

    /// The bytes of table `table`: none, if nothing was ever put there.
    pub fn read(&self, table: usize) -> io::Result<Vec<u8>> {
        match &self.tables[table] {
            Some(blob) => blob.read(&self.file),
            None => Ok(Vec::new()),
        }
    }

    /// Puts each of `changes` (a table, and its bytes from now on) in
    /// place of what was there, all at once: when this returns they are
    /// on disk, and if it fails, or the machine stops before it
    /// returns, none of them is.
    pub fn write(&mut self, changes: &[(usize, &[u8])]) -> io::Result<()> {
        let txn = self.file.begin()?;
        let mut tables = self.tables;
        for (table, bytes) in changes {
            if let Some(old) = &tables[*table] {
                old.free(&txn)?;
            }
            tables[*table] = match bytes.is_empty() {
                true => None,
                false => Some(Blob::write(&txn, bytes)?),
            };
        }
        let mut payload = Vec::with_capacity(8 + TABLES * Blob::BYTES);
        payload.extend_from_slice(MAGIC);
        payload.extend_from_slice(&[FORMAT, TABLES as u8]);
        tables.iter().for_each(|table| Blob::put_option(table, &mut payload));
        txn.commit(&payload)?;
        self.tables = tables;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::testing::{Lost, MemBackend};

    /// What is put in a table is there when the file is opened again;
    /// a table is replaced whole, and emptied by nothing.
    #[test]
    fn tables_are_kept() {
        let mut records = Records::open(MemBackend::new()).unwrap();
        assert!((0..TABLES).all(|t| records.read(t).unwrap().is_empty()));
        let long = vec![7u8; 200_000];
        records.write(&[(0, b"one"), (3, &long)]).unwrap();
        records.write(&[(0, b"another")]).unwrap();
        assert_eq!((records.read(0).unwrap(), records.read(3).unwrap()), (b"another".to_vec(), long.clone()));
        let image = records.file.backend().image(Lost::None);
        let mut again = Records::open(MemBackend::from_image(image)).unwrap();
        assert_eq!((again.read(0).unwrap(), again.read(3).unwrap()), (b"another".to_vec(), long));
        assert!(again.read(1).unwrap().is_empty());
        // Space given up is used again: the file does not grow for ever.
        again.write(&[(3, b""), (5, b"five")]).unwrap();
        assert!(again.read(3).unwrap().is_empty());
        let (used, _) = again.file.space();
        for round in 0..50u8 {
            again.write(&[(5, &[round; 4])]).unwrap();
        }
        assert_eq!(again.file.space().0, used);
    }

    /// A change cut off at any write is all there afterwards, or not at
    /// all: never a part of it.
    #[test]
    fn a_change_is_whole_or_not_at_all() {
        let (before, after): (&[u8], &[u8]) = (b"as it was", b"as it is to be");
        for cut in 0.. {
            let backend = MemBackend::new();
            let mut records = Records::open(backend).unwrap();
            records.write(&[(0, before), (1, before)]).unwrap();
            let start = records.file.backend().ops();
            records.file.backend().crash_at(start + cut);
            let done = records.write(&[(0, after), (1, after)]).is_ok();
            for lost in [Lost::None, Lost::All, Lost::Some(cut)] {
                let image = records.file.backend().image(lost);
                let Ok(found) = Records::open(MemBackend::from_image(image)) else { panic!("cut {cut}") };
                let both = (found.read(0).unwrap(), found.read(1).unwrap());
                assert!(both.0 == both.1 && (both.0 == before || both.0 == after), "cut {cut}: {both:?}");
                if done {
                    assert_eq!(both.0, after, "cut {cut}");
                }
            }
            if done {
                break;
            }
        }
    }
}
