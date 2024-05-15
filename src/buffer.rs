use std::cmp::min;
use std::ptr;

#[derive(Debug, Clone)]
pub(crate) struct Buffer<const N: usize> {
    data: [u8; N],
    position: usize,
}

#[inline]
fn slice_as_array<const N: usize>(slice: &[u8], offset: usize) -> &[u8; N] {
    debug_assert!(slice.len() >= offset + N);
    unsafe { &*(slice.as_ptr().add(offset).cast()) }
}

#[inline]
fn slice_as_array_mut<const N: usize>(slice: &mut [u8], offset: usize) -> &mut [u8; N] {
    debug_assert!(slice.len() >= offset + N);
    unsafe { &mut *(slice.as_mut_ptr().add(offset).cast()) }
}

impl<const N: usize> Default for Buffer<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> AsRef<[u8]> for Buffer<N> {
    fn as_ref(&self) -> &[u8] {
        &self.data[..self.position]
    }
}

impl<const N: usize> AsMut<[u8]> for Buffer<N> {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.data[..self.position]
    }
}

impl<const N: usize> Buffer<N> {
    pub const fn new() -> Self {
        Self {
            data: [0; N],
            position: 0,
        }
    }

    pub fn position(&self) -> usize {
        self.position
    }

    pub fn reset(&mut self) {
        self.position = 0;
    }

    pub fn is_empty(&self) -> bool {
        self.position == 0
    }

    pub fn is_full(&self) -> bool {
        self.position == N
    }

    /// Returns the pointer where the next byte is supposed to go. There may be no more space
    /// The position has garbage values, and it is NOT safe to store to if unsure about the actual
    /// position
    pub unsafe fn ptr_mut(&mut self) -> *mut u8 {
        self.data.as_mut_ptr().add(self.position)
    }

    fn copy_from(&mut self, src: &[u8], offset: usize, len: usize) {
        debug_assert!(offset + len <= src.len());
        debug_assert!(self.position + len <= N);
        unsafe { ptr::copy_nonoverlapping(src.as_ptr().add(offset), self.ptr_mut(), len) }
        self.position += len;
    }

    pub fn pad_zero(&mut self) -> &[u8; N] {
        self.data[self.position..].fill(0);
        self.position = N;
        &self.data
    }

    pub fn append_byte(&mut self, byte: u8) {
        assert!(!self.is_full());
        self.data[self.position] = byte;
        self.position += 1;
    }

    pub fn append(&mut self, data: &[u8]) {
        let len = data.len();
        assert!(len <= N - self.position);
        self.copy_from(data, 0, len);
    }

    pub fn process_blocks<const LAST_SPECIAL: bool>(
        &mut self,
        data: &[u8],
        mut process_block: impl FnMut(&[u8; N]),
    ) {
        let mut offset = 0;
        let length = data.len();

        if !self.is_empty() {
            let take = min(N - self.position, length);

            self.copy_from(data, 0, take);
            offset += take;

            if self.is_full() && (!LAST_SPECIAL || (LAST_SPECIAL && offset < length)) {
                process_block(&self.data);
                self.reset();
            } else {
                return;
            }
        }

        if LAST_SPECIAL {
            while offset + N < length {
                process_block(slice_as_array(data, offset));
                offset += N;
            }
        } else {
            while offset + N <= length {
                process_block(slice_as_array(data, offset));
                offset += N;
            }
        }

        if offset < length {
            self.copy_from(data, offset, length - offset);
        }
    }

    pub fn transform_blocks<const LAST_SPECIAL: bool>(
        &mut self,
        input: &[u8],
        output: &mut [u8],
        mut transform_block: impl FnMut(&[u8; N], &mut [u8; N]),
    ) -> usize {
        debug_assert!(
            output.len() >= {
                let total_len = input.len() + self.position;
                total_len - total_len % N
            }
        );

        let mut i_offset = 0;
        let mut o_offset = 0;
        let length = input.len();

        if !self.is_empty() {
            let take = min(N - self.position, length);

            self.copy_from(input, 0, take);
            i_offset += take;

            if self.is_full() && (!LAST_SPECIAL || (LAST_SPECIAL && i_offset < length)) {
                transform_block(&self.data, slice_as_array_mut(output, 0));
                o_offset += N;
                self.reset();
            } else {
                return 0;
            }
        }

        if LAST_SPECIAL {
            while i_offset + N < length {
                transform_block(
                    slice_as_array(input, i_offset),
                    slice_as_array_mut(output, o_offset),
                );
                i_offset += N;
                o_offset += N;
            }
        } else {
            while i_offset + N <= length {
                transform_block(
                    slice_as_array(input, i_offset),
                    slice_as_array_mut(output, o_offset),
                );
                i_offset += N;
                o_offset += N;
            }
        }

        if i_offset < length {
            self.copy_from(input, i_offset, length - i_offset);
        }

        o_offset
    }
}

impl<const N: usize> Drop for Buffer<N> {
    fn drop(&mut self) {
        self.data.fill(0)
    }
}
