//! Bytes too many for one page: a chain of pages.
//!
//! A block's body is megabytes and a page holds 64 KB, so what is long
//! is cut into pages, each naming the one after it. A [`Blob`] is where
//! the first is and how many bytes there are in all; it is what a record
//! elsewhere holds of the bytes.
//!
//! ```text
//! page := next page (6) | bytes
//! blob := first page (6) | length (4)
//! ```
//!
//! The pages are pages of the state's file like any others: written in a
//! transaction, in place when it commits, freed in another.

use std::io;

use super::backend::Backend;
use super::pagefile::{Extent, MAX_UNITS, PageFile, ReadPages, Txn, UNIT};

/// Bytes a page of a chain holds, after the next page's place.
const CHUNK: usize = Extent::capacity(MAX_UNITS) - 6;
const NONE: Extent = Extent { start: 0, units: 0 };

fn corrupt(what: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, what)
}

/// Bytes kept as a chain of pages.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Blob {
    first: Extent,
    /// Bytes in all.
    pub len: u32,
}

impl Blob {
    /// Serialized size.
    pub const BYTES: usize = 10;

    /// Writes `bytes` as pages of `txn`.
    pub fn write<B: Backend>(txn: &Txn<'_, B>, bytes: &[u8]) -> io::Result<Blob> {
        assert!(!bytes.is_empty() && bytes.len() <= u32::MAX as usize);
        // The last page first: each names the one after it.
        let mut next = NONE;
        let mut page = Vec::with_capacity(6 + CHUNK.min(bytes.len()));
        for chunk in bytes.chunks(CHUNK).rev() {
            page.clear();
            put_extent(&mut page, next);
            page.extend_from_slice(chunk);
            next = txn.write(&page)?;
        }
        Ok(Blob { first: next, len: bytes.len() as u32 })
    }

    /// The bytes.
    pub fn read(&self, pages: &impl ReadPages) -> io::Result<Vec<u8>> {
        let mut out = Vec::with_capacity(self.len as usize);
        self.each_page(pages, &mut |_, data| out.extend_from_slice(data))?;
        match out.len() == self.len as usize {
            true => Ok(out),
            false => Err(corrupt("a chain of pages is not as long as it says")),
        }
    }

    /// Frees the pages.
    pub fn free<B: Backend>(&self, txn: &Txn<'_, B>) -> io::Result<()> {
        let mut chain = Vec::new();
        self.each_page(txn, &mut |e, _| chain.push(e))?;
        chain.into_iter().for_each(|e| txn.free(e));
        Ok(())
    }

    /// Marks the pages in `file`'s map of free space.
    pub fn mark<B: Backend>(&self, file: &PageFile<B>) -> io::Result<()> {
        let mut chain = Vec::new();
        self.each_page(file, &mut |e, _| chain.push(e))?;
        chain.into_iter().try_for_each(|e| file.mark(e))
    }

    pub fn put(&self, out: &mut Vec<u8>) {
        put_extent(out, self.first);
        out.extend_from_slice(&self.len.to_le_bytes());
    }

    /// Reads an optional blob as [`Blob::put_option`] wrote it.
    pub fn get_option(b: &[u8]) -> io::Result<Option<Blob>> {
        let blob = Blob { first: get_extent(&b[..6]), len: u32::from_le_bytes(b[6..10].try_into().unwrap()) };
        match (blob.first.units, blob.len) {
            (0, 0) => Ok(None),
            (1..=MAX_UNITS, 1..) => Ok(Some(blob)),
            _ => Err(corrupt("a chain's place is not one")),
        }
    }

    /// Writes an optional blob: all zero for none.
    pub fn put_option(blob: &Option<Blob>, out: &mut Vec<u8>) {
        match blob {
            Some(b) => b.put(out),
            None => out.extend_from_slice(&[0; Blob::BYTES]),
        }
    }

    /// Calls `f` with each page of the chain, and its bytes.
    fn each_page(&self, pages: &impl ReadPages, f: &mut dyn FnMut(Extent, &[u8])) -> io::Result<()> {
        let mut buf = vec![0u8; MAX_UNITS as usize * UNIT];
        let mut at = self.first;
        // No more pages than the length needs: a chain that goes on is
        // not this blob's.
        for _ in 0..(self.len as usize).div_ceil(CHUNK) {
            if at.units == 0 || at.units > MAX_UNITS {
                return Err(corrupt("a chain of pages ends early"));
            }
            let payload = pages.read_page(at, &mut buf)?;
            let (next, data) = payload.split_at_checked(6).ok_or_else(|| corrupt("a chain's page is not one"))?;
            f(at, data);
            at = get_extent(next);
        }
        match at.units {
            0 => Ok(()),
            _ => Err(corrupt("a chain of pages does not end")),
        }
    }
}

fn put_extent(out: &mut Vec<u8>, e: Extent) {
    out.extend_from_slice(&e.start.to_le_bytes()[..5]);
    out.push(e.units as u8);
}

fn get_extent(b: &[u8]) -> Extent {
    let mut start = [0u8; 8];
    start[..5].copy_from_slice(&b[..5]);
    Extent { start: u64::from_le_bytes(start), units: b[5] as u32 }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::testing::{Lost, MemBackend};
    use crate::test_util::Rng;

    /// Bytes of any length come back as written, their pages are found
    /// by a fresh opening, and freed they are space again.
    #[test]
    fn bytes_of_any_length() {
        let file = PageFile::create(MemBackend::new()).unwrap();
        let empty = file.space().0;
        let mut rng = Rng::new(0xb10b);
        let mut kept = Vec::new();
        for len in [1, 5, CHUNK - 1, CHUNK, CHUNK + 1, 3 * CHUNK, 2_000_000, 2 * CHUNK + 77] {
            let bytes: Vec<u8> = (0..len).map(|_| rng.next_u64() as u8).collect();
            let txn = file.begin().unwrap();
            let blob = Blob::write(&txn, &bytes).unwrap();
            // Read back within the transaction, and after it.
            assert_eq!(blob.read(&txn).unwrap(), bytes);
            txn.commit(&[]).unwrap();
            assert_eq!(blob.read(&file).unwrap(), bytes);
            let mut coded = Vec::new();
            Blob::put_option(&Some(blob), &mut coded);
            assert_eq!((coded.len(), Blob::get_option(&coded).unwrap()), (Blob::BYTES, Some(blob)));
            kept.push((blob, bytes));
        }
        assert_eq!(Blob::get_option(&[0; 10]).unwrap(), None);
        assert!(Blob::get_option(&[0, 0, 0, 0, 0, 0, 1, 0, 0, 0]).is_err());

        // A fresh opening that marks them has the same space in use.
        let again = PageFile::open(MemBackend::from_image(file.backend().image(Lost::All))).unwrap();
        for (blob, bytes) in &kept {
            blob.mark(&again).unwrap();
            assert_eq!(blob.read(&again).unwrap(), *bytes);
        }
        again.seal();
        assert_eq!(again.space().0, file.space().0);
        // A length that is not the chain's is found out.
        let (blob, _) = kept[5];
        assert!(Blob { len: blob.len + CHUNK as u32, ..blob }.read(&file).is_err());
        assert!(Blob { len: blob.len - CHUNK as u32, ..blob }.read(&file).is_err());
        assert!(Blob { len: blob.len - 1, ..blob }.read(&file).is_err());

        let txn = file.begin().unwrap();
        kept.iter().for_each(|(blob, _)| blob.free(&txn).unwrap());
        txn.commit(&[]).unwrap();
        assert_eq!(file.space().0, empty);
    }
}
