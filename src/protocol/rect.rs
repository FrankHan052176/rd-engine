//! The presentation contract shared by every rectangle-based protocol.
//!
//! RFB (VNC) and RDP adapters share this presentation sink and damage model.
//! Their upstream libraries own decoding and their decoded framebuffers; the
//! adapters borrow those images and copy only damaged rows into this sink.
//! No cloned full-frame delivery queue or separate presentation implementation
//! belongs to either protocol adapter.
//!
//! The current adapters require BGRA8888. VNC negotiates that layout through
//! LibVNCClient; IronRDP decodes to BgrA32. Other target layouts are rejected
//! rather than silently converted by this boundary.

/// A rectangle in remote framebuffer coordinates. Never silently clipped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Rect {
    pub x: i32,
    pub y: i32,
    pub width: i32,
    pub height: i32,
}

impl Rect {
    pub fn new(x: i32, y: i32, width: i32, height: i32) -> Self {
        Self {
            x,
            y,
            width,
            height,
        }
    }

    /// Rejects empty and negative extents, and negative origins.
    pub fn validate(&self) -> Result<(), PixelError> {
        if self.x < 0 || self.y < 0 || self.width <= 0 || self.height <= 0 {
            return Err(PixelError::InvalidRect);
        }
        Ok(())
    }

    pub fn contains(&self, other: &Rect) -> bool {
        other.x >= self.x
            && other.y >= self.y
            && other.x + other.width <= self.x + self.width
            && other.y + other.height <= self.y + self.height
    }

    /// Bounding box of two rectangles, or the other one when either is absent.
    pub fn union(&self, other: &Rect) -> Rect {
        let x = self.x.min(other.x);
        let y = self.y.min(other.y);
        let right = (self.x + self.width).max(other.x + other.width);
        let bottom = (self.y + self.height).max(other.y + other.height);
        Rect::new(x, y, right - x, bottom - y)
    }

    pub fn pixels(&self) -> i64 {
        i64::from(self.width) * i64::from(self.height)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PixelError {
    InvalidRect,
    OutOfBounds,
    UnsupportedFormat,
    GeometryRejected,
}

impl std::fmt::Display for PixelError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidRect => f.write_str("Rectangle is empty or has a negative extent"),
            Self::OutOfBounds => f.write_str("Rectangle escapes the framebuffer"),
            Self::UnsupportedFormat => f.write_str("Pixel format is not supported by this sink"),
            Self::GeometryRejected => f.write_str("Presentation sink refused the geometry"),
        }
    }
}

impl std::error::Error for PixelError {}

/// Byte layout of one pixel. `shifts` are bit positions inside the little- or
/// big-endian integer the wire format defines.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PixelLayout {
    pub bytes_per_pixel: u8,
    pub red_shift: u8,
    pub green_shift: u8,
    pub blue_shift: u8,
    pub big_endian: bool,
}

impl PixelLayout {
    /// What the OHOS surface buffer is natively written as.
    pub const fn bgra8888() -> Self {
        Self {
            bytes_per_pixel: 4,
            red_shift: 16,
            green_shift: 8,
            blue_shift: 0,
            big_endian: false,
        }
    }

    pub const fn rgba8888() -> Self {
        Self {
            bytes_per_pixel: 4,
            red_shift: 0,
            green_shift: 8,
            blue_shift: 16,
            big_endian: false,
        }
    }

    /// The 32-bit RFB pixel value for the supported shifts, as the wire's
    /// little-/big-endian integer. Only the 8/8/8 layouts above are accepted;
    /// anything else would need a per-pixel conversion on the hot path.
    pub fn pack(&self, red: u8, green: u8, blue: u8) -> Option<u32> {
        if self.bytes_per_pixel != 4 || self.red_shift % 8 != 0 || self.green_shift % 8 != 0
            || self.blue_shift % 8 != 0
            || self.red_shift > 24
            || self.green_shift > 24
            || self.blue_shift > 24
        {
            return None;
        }
        let value = (u32::from(red) << self.red_shift)
            | (u32::from(green) << self.green_shift)
            | (u32::from(blue) << self.blue_shift);
        Some(if self.big_endian {
            value.to_be()
        } else {
            value.to_le()
        })
    }
}

/// A writable rectangle inside the presentation framebuffer.
///
/// Rows are addressed through `stride`, which may exceed `width *
/// bytes_per_pixel` because the rectangle is a window into a larger buffer.
/// Every accessor is bounds-checked; the decoder cannot write outside the
/// rectangle it was handed.
pub struct RectBuf<'a> {
    pixels: &'a mut [u8],
    stride: usize,
    rect: Rect,
    bytes_per_pixel: usize,
    /// Byte offset of the rectangle's first pixel inside `pixels`.
    base: usize,
}

impl<'a> RectBuf<'a> {
    /// `origin` is where the whole framebuffer starts inside `pixels`; a sink
    /// that owns a plain framebuffer passes `(0, 0)`.
    pub fn new(
        pixels: &'a mut [u8],
        stride: usize,
        origin: (i32, i32),
        rect: Rect,
        bytes_per_pixel: usize,
    ) -> Self {
        let x = origin.0.saturating_add(rect.x).max(0) as usize;
        let y = origin.1.saturating_add(rect.y).max(0) as usize;
        let base = y
            .saturating_mul(stride)
            .saturating_add(x.saturating_mul(bytes_per_pixel));
        Self {
            pixels,
            stride,
            rect,
            bytes_per_pixel,
            base,
        }
    }

    pub fn rect(&self) -> Rect {
        self.rect
    }

    /// Row `y` (rectangle-local) as exactly `width * bytes_per_pixel` bytes.
    pub fn row(&mut self, y: i32) -> Option<&mut [u8]> {
        if y < 0 || y >= self.rect.height {
            return None;
        }
        let start = self.base.checked_add((y as usize).checked_mul(self.stride)?)?;
        let end = start.checked_add(self.rect.width as usize * self.bytes_per_pixel)?;
        self.pixels.get_mut(start..end)
    }

    /// Byte offset of one pixel, already bounds-checked against the rectangle.
    pub fn offset(&self, x: i32, y: i32) -> Option<usize> {
        if x < 0 || y < 0 || x >= self.rect.width || y >= self.rect.height {
            return None;
        }
        let row = self.base.checked_add((y as usize).checked_mul(self.stride)?)?;
        let offset = row.checked_add((x as usize).checked_mul(self.bytes_per_pixel)?)?;
        (offset + self.bytes_per_pixel <= self.pixels.len()).then_some(offset)
    }

    /// Writes one already-packed wire pixel, in the sink's byte order.
    pub fn put_pixel(&mut self, x: i32, y: i32, value: u32) {
        let Some(offset) = self.offset(x, y) else {
            return;
        };
        let bytes = if self.bytes_per_pixel == 4 {
            value.to_le_bytes()
        } else {
            // Only 4-byte layouts are negotiated; 3-byte ones stay unreachable.
            return;
        };
        self.pixels[offset..offset + 4].copy_from_slice(&bytes);
    }

    /// Fills one row from a wire-format run (Raw, Hextile, RLE, ...).
    pub fn put_row(&mut self, y: i32, src: &[u8]) -> bool {
        let width = self.rect.width as usize * self.bytes_per_pixel;
        if src.len() < width {
            return false;
        }
        match self.row(y) {
            Some(row) => {
                row.copy_from_slice(&src[..width]);
                true
            }
            None => false,
        }
    }
}

/// Implemented by the presentation stage (one per session).
///
/// A sink owns one presentation framebuffer. Protocol libraries can own their
/// decoded image separately; adapters borrow it and write damaged windows here.
/// This contract does not imply zero-copy decoding or GPU presentation.
pub trait PixelTarget: Send {
    /// Layout accepted by this sink. Each adapter validates compatibility before
    /// handing decoded pixels to it.
    fn layout(&self) -> PixelLayout;

    /// Current framebuffer extent in pixels.
    fn size(&self) -> (i32, i32);

    /// Writable window for one rectangle. Rectangles outside the framebuffer
    /// are rejected; they are never clipped, because a server that disagrees
    /// about geometry is a protocol error rather than something to hide.
    fn rect_mut(&mut self, rect: Rect) -> Result<RectBuf<'_>, PixelError>;

    /// Records presentation damage once the rectangle is fully written.
    fn damage(&mut self, rect: Rect);

    /// In-framebuffer copy (RFB CopyRect). `src` must be fully inside the
    /// framebuffer; overlapping copies must behave as if `src` were snapshotted
    /// first, which the RFB server guarantees but a local copy must respect.
    fn copy_rect(&mut self, dst: Rect, src_x: i32, src_y: i32) -> Result<(), PixelError>;

    /// Applies a new geometry (RFB DesktopSize). The sink keeps its promise
    /// about which layouts it can absorb, so a resize may reallocate here.
    fn resize(&mut self, width: i32, height: i32) -> Result<(), PixelError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rect_rejects_and_unions() {
        assert!(Rect::new(0, 0, 1, 1).validate().is_ok());
        assert_eq!(Rect::new(-1, 0, 1, 1).validate(), Err(PixelError::InvalidRect));
        assert_eq!(Rect::new(0, 0, 0, 1).validate(), Err(PixelError::InvalidRect));
        let a = Rect::new(4, 4, 8, 8);
        let b = Rect::new(0, 0, 3, 3);
        assert_eq!(a.union(&b), Rect::new(0, 0, 12, 12));
        assert!(a.contains(&Rect::new(4, 4, 8, 8)));
        assert!(!a.contains(&b));
    }

    #[test]
    fn bgra_packs_blue_in_the_low_byte() {
        let layout = PixelLayout::bgra8888();
        let packed = layout.pack(0x11, 0x22, 0x33).unwrap();
        assert_eq!(packed.to_le_bytes(), [0x33, 0x22, 0x11, 0x00]);
        let rgba = PixelLayout::rgba8888();
        assert_eq!(
            rgba.pack(0x11, 0x22, 0x33).unwrap().to_le_bytes(),
            [0x11, 0x22, 0x33, 0x00]
        );
    }

    #[test]
    fn unaligned_shifts_are_refused_rather_than_converted() {
        let layout = PixelLayout {
            bytes_per_pixel: 2,
            red_shift: 11,
            green_shift: 5,
            blue_shift: 0,
            big_endian: false,
        };
        assert!(layout.pack(1, 2, 3).is_none());
    }

    #[test]
    fn rect_buf_writes_through_stride_and_refuses_out_of_rect() {
        // 4x2 framebuffer (16-byte rows), rectangle covers x=1..4 in both rows.
        let mut framebuffer = vec![0u8; 16 * 2];
        let window = Rect::new(1, 0, 3, 2);
        let mut buf = RectBuf::new(&mut framebuffer, 16, (0, 0), window, 4);
        assert!(buf.put_row(0, &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]));
        assert!(buf.put_row(1, &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]));
        // A row shorter than the rectangle width is refused, not zero-filled.
        assert!(!buf.put_row(1, &[0; 8]));
        assert_eq!(buf.row(-1), None);
        assert_eq!(buf.row(2), None);
        // Rectangle-local coordinates, so x=3 is one past this window.
        assert_eq!(buf.offset(3, 0), None);
        assert_eq!(buf.offset(2, 1), Some(16 + 3 * 4));
        buf.put_pixel(0, 0, 0xdead_beef);
        // Row 0 of the rectangle starts at x=1, so bytes 0..4 stay untouched
        // and the pixel just overwritten lands at 4..8.
        assert_eq!(framebuffer[4..8], 0xdead_beefu32.to_le_bytes());
        assert_eq!(framebuffer[0..4], [0, 0, 0, 0]);
        assert_eq!(framebuffer[8..16], [5, 6, 7, 8, 9, 10, 11, 12]);
        // Row 1 starts at the second stride, not immediately after row 0, so
        // its first four bytes are the untouched column left of the window.
        assert_eq!(framebuffer[16..20], [0, 0, 0, 0]);
        assert_eq!(framebuffer[20..32], [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]);
    }
}
