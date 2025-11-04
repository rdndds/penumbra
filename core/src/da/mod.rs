/*
    SPDX-License-Identifier: AGPL-3.0-or-later
    SPDX-FileCopyrightText: 2025 Shomy
*/
pub mod dafile;
pub mod protocol;
pub mod xflash;
pub use dafile::{DA, DAEntryRegion, DAFile, DAType};
pub use protocol::DAProtocol;
pub use xflash::XFlash;
