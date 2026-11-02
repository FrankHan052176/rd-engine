//! Annex-B access-unit inspection shared by every path that carries compressed
//! video without decoding it.
//!
//! The publisher needs three answers about one access unit: whether it contains
//! a coded picture (as opposed to
//! standalone codec data, SEI or an access-unit delimiter), whether that picture
//! is a random-access point, and which SPS/PPS — or VPS/SPS/PPS — the stream
//! currently carries. The encoder path in `platform::publisher` uses this
//! scanner to inspect the stream before publishing it.
//!
//! This module only reads. It keeps no stream state that is not codec metadata:
//! [`ParameterSets`] holds the three parameter-set slots (bytestream form, start
//! code included) and, for callers that need it, a bounded prefix of standalone
//! metadata to attach to the next real picture. Nothing here decodes, resamples
//! or trusts a caller-supplied key flag — H264 and H265 answers come from the NAL
//! types in the bytes themselves.
//!
//! VP8/VP9 are not Annex-B streams. [`ParameterSets::inspect`] refuses them by
//! name ([`AnnexBError::NotAnnexB`]) instead of scanning their bytes as NAL units
//! and inventing an answer; a caller that forwards them keeps the
//! wire's own key flag and passes no parameter sets.

use crate::viewer::decoder::VideoCodec;

/// Bound on one stored parameter set (one NAL unit in bytestream form).
///
/// It is a third of the metadata budget the encoder path already reserved, which
/// is what keeps the three slots together inside that budget.
pub const PARAMETER_SET_LIMIT: usize = 256 * 1024 / 3;

/// Bound on the standalone metadata a caller may hold for the next picture.
pub const PENDING_LIMIT: usize = 256 * 1024;

/// What one access unit turned out to contain.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Inspected {
    /// At least one VCL NAL unit: a coded picture, not codec data or metadata.
    pub picture: bool,
    /// At least one random-access picture (H264 IDR, H265 IRAP).
    pub key: bool,
}

/// Why an access unit could not be inspected, or a parameter set is unusable.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AnnexBError {
    /// Not a series of length-prefixed NAL units, or a NAL header this codec
    /// does not allow.
    Invalid,
    /// The codec has no Annex-B framing to inspect.
    NotAnnexB,
    /// One parameter set is larger than [`PARAMETER_SET_LIMIT`].
    ParameterSetTooLarge,
    /// Adding this metadata would exceed [`PENDING_LIMIT`].
    PendingTooLarge,
    /// The parameter sets this codec needs are not all present yet.
    MissingParameterSets,
}

/// The parameter sets of one H264/H265 stream, as bytestream NAL units.
///
/// Slots are SPS/PPS for H264 (unused, SPS, PPS) and VPS/SPS/PPS for H265. Order
/// is the slot order, so [`ParameterSets::prepend`] emits exactly the
/// "SPS, PPS" or "VPS, SPS, PPS" prefix each codec expects.
#[derive(Clone, Default)]
pub struct ParameterSets {
    sets: [Option<Vec<u8>>; 3],
    /// Standalone CSD/SEI/AUD kept until a real picture arrives; metadata is
    /// attached to that picture, never emitted or counted as a synthetic frame.
    pending: Vec<u8>,
}

impl ParameterSets {
    /// Walks one access unit, recording any parameter sets it carries.
    ///
    /// Answers what the unit is and what the newest sets are; it changes nothing
    /// about the caller's stream beyond those slots and never treats codec data
    /// as a picture. A unit whose framing or NAL headers are not legal is
    /// refused, not partially accepted.
    pub fn inspect(&mut self, codec: VideoCodec, data: &[u8]) -> Result<Inspected, AnnexBError> {
        let h264 = match codec {
            VideoCodec::H264 => true,
            VideoCodec::H265 => false,
            VideoCodec::Vp8 | VideoCodec::Vp9 => return Err(AnnexBError::NotAnnexB),
        };
        fn start(data: &[u8], i: usize) -> usize {
            if data.get(i..i + 4) == Some(&[0, 0, 0, 1]) {
                4
            } else if data.get(i..i + 3) == Some(&[0, 0, 1]) {
                3
            } else {
                0
            }
        }
        if start(data, 0) == 0 {
            return Err(AnnexBError::Invalid);
        }
        let (mut offset, mut picture, mut key) = (0, false, false);
        while offset < data.len() {
            let prefix = start(data, offset);
            if prefix == 0 || offset + prefix >= data.len() {
                return Err(AnnexBError::Invalid);
            }
            let header = offset + prefix;
            let mut end = header + 1;
            while end < data.len() && start(data, end) == 0 {
                end += 1;
            }
            let kind = if h264 {
                data[header] & 31
            } else {
                (data[header] >> 1) & 63
            };
            if data[header] & 0x80 != 0
                || (h264 && kind == 0)
                || (!h264 && (header + 1 >= end || data[header + 1] & 7 == 0))
            {
                return Err(AnnexBError::Invalid);
            }
            let slot = if h264 {
                picture |= (1..=5).contains(&kind);
                key |= kind == 5;
                match kind {
                    7 => Some(1),
                    8 => Some(2),
                    _ => None,
                }
            } else {
                picture |= kind <= 31;
                key |= (16..=23).contains(&kind);
                match kind {
                    32 => Some(0),
                    33 => Some(1),
                    34 => Some(2),
                    _ => None,
                }
            };
            if let Some(slot) = slot {
                if end - offset > PARAMETER_SET_LIMIT {
                    return Err(AnnexBError::ParameterSetTooLarge);
                }
                self.sets[slot] = Some(data[offset..end].to_vec());
            }
            offset = end;
        }
        Ok(Inspected { picture, key })
    }

    /// Total bytestream length of the parameter sets `codec` requires, or
    /// [`AnnexBError::MissingParameterSets`] while one of them is absent.
    pub fn length(&self, codec: VideoCodec) -> Result<usize, AnnexBError> {
        let first = match codec {
            VideoCodec::H264 => 1,
            VideoCodec::H265 => 0,
            VideoCodec::Vp8 | VideoCodec::Vp9 => return Err(AnnexBError::NotAnnexB),
        };
        self.sets[first..].iter().try_fold(0usize, |total, set| {
            set.as_ref()
                .map(|set| total + set.len())
                .ok_or(AnnexBError::MissingParameterSets)
        })
    }

    /// Appends every stored parameter set, in decoder configuration order.
    pub fn prepend(&self, out: &mut Vec<u8>) {
        for set in self.sets.iter().flatten() {
            out.extend_from_slice(set);
        }
    }

    /// Whether `other` carries different parameter set bytes than this value.
    ///
    /// Every slot is compared, so a set that this codec does not use cannot make
    /// two otherwise identical streams look different: only `inspect` writes a
    /// slot, and it writes only the slots of the codec it was given. The pending
    /// metadata is not configuration and is not compared.
    pub fn differs_from(&self, other: &Self) -> bool {
        self.sets != other.sets
    }

    /// Keeps standalone metadata for the next picture, within [`PENDING_LIMIT`].
    pub fn push_pending(&mut self, data: &[u8]) -> Result<(), AnnexBError> {
        if data.len() > PENDING_LIMIT.saturating_sub(self.pending.len()) {
            return Err(AnnexBError::PendingTooLarge);
        }
        self.pending.extend_from_slice(data);
        Ok(())
    }

    /// The standalone metadata kept for the next picture.
    pub fn pending(&self) -> &[u8] {
        &self.pending
    }

    /// Drops the kept metadata, which a caller does once it is attached to a
    /// picture it actually emitted.
    pub fn clear_pending(&mut self) {
        self.pending.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// AUD, SPS, PPS and an IDR, framed the way both callers receive them.
    fn h264_key() -> Vec<u8> {
        let mut unit = Vec::new();
        for nal in [
            &[0x09, 0xf0][..],
            &[0x67, 0x42, 0x00, 0x1f][..],
            &[0x68, 0xce, 0x3c, 0x80][..],
            &[0x65, 0x88, 0x84][..],
        ] {
            unit.extend_from_slice(&[0, 0, 0, 1]);
            unit.extend_from_slice(nal);
        }
        unit
    }

    fn h265_key() -> Vec<u8> {
        let mut unit = Vec::new();
        for nal in [
            &[0x40, 0x01, 0x0c][..],
            &[0x42, 0x01, 0x01][..],
            &[0x44, 0x01, 0xc0][..],
            &[0x26, 0x01, 0xaf][..],
        ] {
            unit.extend_from_slice(&[0, 0, 0, 1]);
            unit.extend_from_slice(nal);
        }
        unit
    }

    /// Random access is read from the NAL types, and the sets that a decoder
    /// configuration needs come back in bytestream form and in order.
    #[test]
    fn pictures_and_parameter_sets_come_from_the_nals() {
        let mut sets = ParameterSets::default();
        let unit = h264_key();
        assert_eq!(
            sets.inspect(VideoCodec::H264, &unit),
            Ok(Inspected {
                picture: true,
                key: true
            })
        );
        assert_eq!(sets.length(VideoCodec::H264), Ok((4 + 4) + (4 + 4)));
        let mut configuration = Vec::new();
        sets.prepend(&mut configuration);
        let mut expected = Vec::new();
        expected.extend_from_slice(&[0, 0, 0, 1, 0x67, 0x42, 0x00, 0x1f]);
        expected.extend_from_slice(&[0, 0, 0, 1, 0x68, 0xce, 0x3c, 0x80]);
        assert_eq!(
            configuration, expected,
            "SPS then PPS, start code included, exactly as the helper received them"
        );

        let mut sets = ParameterSets::default();
        let unit = h265_key();
        assert_eq!(
            sets.inspect(VideoCodec::H265, &unit),
            Ok(Inspected {
                picture: true,
                key: true
            })
        );
        let mut configuration = Vec::new();
        sets.prepend(&mut configuration);
        let mut expected = Vec::new();
        for nal in [
            &[0, 0, 0, 1, 0x40, 0x01, 0x0c][..],
            &[0, 0, 0, 1, 0x42, 0x01, 0x01][..],
            &[0, 0, 0, 1, 0x44, 0x01, 0xc0][..],
        ] {
            expected.extend_from_slice(nal);
        }
        assert_eq!(
            configuration, expected,
            "VPS, SPS then PPS, start code included"
        );

        // Codec data alone is not a picture, and a non-IDR slice is not a key.
        let pps_only = [0, 0, 1, 0x68, 0xce, 0x3c, 0x80];
        let mut sets = ParameterSets::default();
        assert_eq!(
            sets.inspect(VideoCodec::H264, &pps_only),
            Ok(Inspected {
                picture: false,
                key: false
            })
        );
        assert_eq!(
            sets.length(VideoCodec::H264),
            Err(AnnexBError::MissingParameterSets)
        );
        let slice = [0, 0, 1, 0x41, 0x9a];
        assert_eq!(
            sets.inspect(VideoCodec::H264, &slice),
            Ok(Inspected {
                picture: true,
                key: false
            })
        );
    }

    /// Framing, size and codec bounds are answers, never a silent truncation.
    #[test]
    fn unbounded_or_foreign_input_is_refused() {
        let mut sets = ParameterSets::default();
        for refused in [&[0u8; 0][..], &[0x00, 0x00, 0x01][..], &[0x67, 0x42][..]] {
            assert_eq!(
                sets.inspect(VideoCodec::H264, refused),
                Err(AnnexBError::Invalid)
            );
        }
        // H265 needs a two-byte header whose temporal_id_plus1 is nonzero.
        assert_eq!(
            sets.inspect(VideoCodec::H265, &[0, 0, 1, 0x26, 0x00]),
            Err(AnnexBError::Invalid)
        );
        assert_eq!(
            sets.inspect(VideoCodec::Vp8, &[0, 0, 1, 0x67]),
            Err(AnnexBError::NotAnnexB)
        );
        assert_eq!(sets.length(VideoCodec::Vp9), Err(AnnexBError::NotAnnexB));

        let mut oversized = vec![0, 0, 0, 1, 0x67];
        oversized.resize(PARAMETER_SET_LIMIT + 1, 0x11);
        assert_eq!(
            ParameterSets::default().inspect(VideoCodec::H264, &oversized),
            Err(AnnexBError::ParameterSetTooLarge)
        );
        assert_eq!(
            ParameterSets::default().push_pending(&vec![0x00; PENDING_LIMIT + 1]),
            Err(AnnexBError::PendingTooLarge)
        );
    }
}
