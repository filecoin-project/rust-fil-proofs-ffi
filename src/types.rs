use std::ptr;

use drop_struct_macro_derive::DropStructMacro;
// `CodeAndMessage` is the trait implemented by `code_and_message_impl`
use ffi_toolkit::{code_and_message_impl, free_c_str, CodeAndMessage, FCPResponseStatus};
use filecoin_proofs::{PieceInfo, UnpaddedBytesAmount};
use std::io::{Error, SeekFrom};

/// FileDescriptorRef does not drop its file descriptor when it is dropped. Its
/// owner must manage the lifecycle of the file descriptor.
pub struct FileDescriptorRef(nodrop::NoDrop<std::fs::File>);

impl FileDescriptorRef {
    #[cfg(not(target_os = "windows"))]
    pub unsafe fn new(raw: std::os::unix::io::RawFd) -> Self {
        use std::os::unix::io::FromRawFd;
        FileDescriptorRef(nodrop::NoDrop::new(std::fs::File::from_raw_fd(raw)))
    }
}

impl std::io::Read for FileDescriptorRef {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.0.read(buf)
    }
}

impl std::io::Write for FileDescriptorRef {
    fn write(&mut self, buf: &[u8]) -> Result<usize, Error> {
        self.0.write(buf)
    }

    fn flush(&mut self) -> Result<(), Error> {
        self.0.flush()
    }
}

impl std::io::Seek for FileDescriptorRef {
    fn seek(&mut self, pos: SeekFrom) -> Result<u64, Error> {
        self.0.seek(pos)
    }
}

#[repr(C)]
#[derive(Clone)]
pub struct FFIPublicPieceInfo {
    pub num_bytes: u64,
    pub comm_p: [u8; 32],
}

impl From<FFIPublicPieceInfo> for PieceInfo {
    fn from(x: FFIPublicPieceInfo) -> Self {
        let FFIPublicPieceInfo { num_bytes, comm_p } = x;
        PieceInfo {
            commitment: comm_p,
            size: UnpaddedBytesAmount(num_bytes),
        }
    }
}

#[repr(C)]
#[derive(DropStructMacro)]
pub struct WriteWithAlignmentResponse {
    pub comm_p: [u8; 32],
    pub error_msg: *const libc::c_char,
    pub left_alignment_unpadded: u64,
    pub status_code: FCPResponseStatus,
    pub total_write_unpadded: u64,
}

impl Default for WriteWithAlignmentResponse {
    fn default() -> WriteWithAlignmentResponse {
        WriteWithAlignmentResponse {
            comm_p: Default::default(),
            status_code: FCPResponseStatus::FCPNoError,
            error_msg: ptr::null(),
            left_alignment_unpadded: 0,
            total_write_unpadded: 0,
        }
    }
}

code_and_message_impl!(WriteWithAlignmentResponse);

#[repr(C)]
#[derive(DropStructMacro)]
pub struct WriteWithoutAlignmentResponse {
    pub comm_p: [u8; 32],
    pub error_msg: *const libc::c_char,
    pub status_code: FCPResponseStatus,
    pub total_write_unpadded: u64,
}

impl Default for WriteWithoutAlignmentResponse {
    fn default() -> WriteWithoutAlignmentResponse {
        WriteWithoutAlignmentResponse {
            comm_p: Default::default(),
            status_code: FCPResponseStatus::FCPNoError,
            error_msg: ptr::null(),
            total_write_unpadded: 0,
        }
    }
}

code_and_message_impl!(WriteWithoutAlignmentResponse);

#[repr(C)]
#[derive(DropStructMacro)]
pub struct SealPreCommitResponse {
    pub status_code: FCPResponseStatus,
    pub error_msg: *const libc::c_char,
}

impl Default for SealPreCommitResponse {
    fn default() -> SealPreCommitResponse {
        SealPreCommitResponse {
            status_code: FCPResponseStatus::FCPNoError,
            error_msg: ptr::null(),
        }
    }
}

code_and_message_impl!(SealPreCommitResponse);

#[repr(C)]
#[derive(DropStructMacro)]
pub struct SealCommitResponse {
    pub status_code: FCPResponseStatus,
    pub error_msg: *const libc::c_char,
}

impl Default for SealCommitResponse {
    fn default() -> SealCommitResponse {
        SealCommitResponse {
            status_code: FCPResponseStatus::FCPNoError,
            error_msg: ptr::null(),
        }
    }
}

code_and_message_impl!(SealCommitResponse);

#[repr(C)]
#[derive(DropStructMacro)]
pub struct UnsealResponse {
    pub status_code: FCPResponseStatus,
    pub error_msg: *const libc::c_char,
}

impl Default for UnsealResponse {
    fn default() -> UnsealResponse {
        UnsealResponse {
            status_code: FCPResponseStatus::FCPNoError,
            error_msg: ptr::null(),
        }
    }
}

code_and_message_impl!(UnsealResponse);

#[repr(C)]
#[derive(DropStructMacro)]
pub struct VerifySealResponse {
    pub status_code: FCPResponseStatus,
    pub error_msg: *const libc::c_char,
    pub is_valid: bool,
}

impl Default for VerifySealResponse {
    fn default() -> VerifySealResponse {
        VerifySealResponse {
            status_code: FCPResponseStatus::FCPNoError,
            error_msg: ptr::null(),
            is_valid: false,
        }
    }
}

code_and_message_impl!(VerifySealResponse);

#[repr(C)]
#[derive(DropStructMacro)]
pub struct VerifyPoStResponse {
    pub status_code: FCPResponseStatus,
    pub error_msg: *const libc::c_char,
    pub is_valid: bool,
}

impl Default for VerifyPoStResponse {
    fn default() -> VerifyPoStResponse {
        VerifyPoStResponse {
            status_code: FCPResponseStatus::FCPNoError,
            error_msg: ptr::null(),
            is_valid: false,
        }
    }
}

code_and_message_impl!(VerifyPoStResponse);

#[repr(C)]
#[derive(DropStructMacro)]
pub struct GeneratePieceCommitmentResponse {
    pub status_code: FCPResponseStatus,
    pub error_msg: *const libc::c_char,
    pub comm_p: [u8; 32],
    /// The number of unpadded bytes in the original piece plus any (unpadded)
    /// alignment bytes added to create a whole merkle tree.
    pub num_bytes_aligned: u64,
}

impl Default for GeneratePieceCommitmentResponse {
    fn default() -> GeneratePieceCommitmentResponse {
        GeneratePieceCommitmentResponse {
            status_code: FCPResponseStatus::FCPNoError,
            comm_p: Default::default(),
            error_msg: ptr::null(),
            num_bytes_aligned: 0,
        }
    }
}

code_and_message_impl!(GeneratePieceCommitmentResponse);

#[repr(C)]
#[derive(DropStructMacro)]
pub struct GenerateDataCommitmentResponse {
    pub status_code: FCPResponseStatus,
    pub error_msg: *const libc::c_char,
    pub comm_d: [u8; 32],
}

impl Default for GenerateDataCommitmentResponse {
    fn default() -> GenerateDataCommitmentResponse {
        GenerateDataCommitmentResponse {
            status_code: FCPResponseStatus::FCPNoError,
            comm_d: Default::default(),
            error_msg: ptr::null(),
        }
    }
}

code_and_message_impl!(GenerateDataCommitmentResponse);
