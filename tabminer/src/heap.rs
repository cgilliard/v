//! How much memory the program holds: every allocation counted.
//!
//! [`Counting`] is the system's allocator with two numbers beside it:
//! the bytes held now, and the most ever held. A program that makes it
//! its allocator (`#[global_allocator]`, as the node does) can say both
//! at any moment, on any system, for what two atomic additions an
//! allocation cost. Where it is not the allocator (the library's own
//! tests) both numbers are zero.
//!
//! What is counted is what was asked for: not what the system's
//! allocator keeps besides, nor the stacks of threads, nor the program
//! itself. It is the part of a node's memory that the node decides.

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};

static NOW: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);

/// The system's allocator, counted.
pub struct Counting;

fn took(bytes: usize) {
    let now = NOW.fetch_add(bytes, Ordering::Relaxed) + bytes;
    PEAK.fetch_max(now, Ordering::Relaxed);
}

// SAFETY: every call is the system allocator's own, with the arguments
// given; the counting beside it touches nothing but two numbers.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: the caller's contract is `System`'s.
        let p = unsafe { System.alloc(layout) };
        if !p.is_null() {
            took(layout.size());
        }
        p
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        // SAFETY: the caller's contract is `System`'s.
        let p = unsafe { System.alloc_zeroed(layout) };
        if !p.is_null() {
            took(layout.size());
        }
        p
    }

    unsafe fn dealloc(&self, p: *mut u8, layout: Layout) {
        // SAFETY: the caller's contract is `System`'s.
        unsafe { System.dealloc(p, layout) };
        NOW.fetch_sub(layout.size(), Ordering::Relaxed);
    }

    unsafe fn realloc(&self, p: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        // SAFETY: the caller's contract is `System`'s.
        let q = unsafe { System.realloc(p, layout, new_size) };
        if !q.is_null() {
            NOW.fetch_sub(layout.size(), Ordering::Relaxed);
            took(new_size);
        }
        q
    }
}

/// The bytes held now.
pub fn now() -> usize {
    NOW.load(Ordering::Relaxed)
}

/// The most bytes ever held at once, since the program began or since
/// [`reset_peak`].
pub fn peak() -> usize {
    PEAK.load(Ordering::Relaxed)
}

/// Counts the most held afresh, from what is held now: for the most a
/// stretch of work holds.
pub fn reset_peak() {
    PEAK.store(now(), Ordering::Relaxed);
}
