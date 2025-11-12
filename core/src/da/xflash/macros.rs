/*
    SPDX-License-Identifier: AGPL-3.0-or-later
    SPDX-FileCopyrightText: 2025 Shomy
*/

macro_rules! status {
    ($self:ident, $expected:expr, $msg:expr) => {{
        let status = $self.get_status().await?;
        if status != $expected {
            let xflash_err = crate::error::XFlashError::from_code(status);
            log::error!("{}: 0x{:08X} ({})", $msg, status, xflash_err);
            return Err(Error::XFlash(xflash_err));
        }
    }};

    ($self:ident, $expected:expr) => {{
        let status = $self.get_status().await?;
        if status != $expected {
            let xflash_err = crate::error::XFlashError::from_code(status);
            log::error!("Status is not expected: 0x{:08X} ({})", status, xflash_err);
            return Err(Error::XFlash(xflash_err));
        }
    }};
}

macro_rules! status_ok {
    ($self:ident, $msg:expr) => {{
        status!($self, 0, $msg);
    }};
    ($self:ident) => {{
        status!($self, 0);
    }};
}

macro_rules! status_any {
    ($self:ident, $($valid:expr),+ $(,)?) => {{
        let status = $self.get_status().await?;
        if ![$($valid),+].contains(&status) {
            let xflash_err = XFlashError::from_code(status);
            error!("Status is not expected: 0x{:08X} ({})", status, xflash_err);
            return Err(Error::XFlash(xflash_err));
        }
    }};
}
