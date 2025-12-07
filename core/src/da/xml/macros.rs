/*
    SPDX-License-Identifier: AGPL-3.0-or-later
    SPDX-FileCopyrightText: 2025 Shomy
*/

/// Constructs a DA XML cmd with positional arguments,
/// and sends it.
/// If `None` is provided, and a default value exists, the default is used.
macro_rules! xmlcmd {
    ($self:expr, $cmd_ty:ty $(, $arg:expr )* $(,)?) => {{
        let cmd = <$cmd_ty>::new( $( $arg ),* );
        $self.send_cmd(&cmd).await
    }};
}

/// Constructs a DA XML cmd with positional arguments,
/// sends it, and then aknowledges CMD:END
macro_rules! xmlcmd_e {
    ($self:expr, $cmd_ty:ty $(, $arg:expr )* $(,)?) => {{
        let cmd = <$cmd_ty>::new( $( $arg ),* );
        $self.send_cmd(&cmd).await?;
        $self.lifetime_ack(crate::da::xml::cmds::XmlCmdLifetime::CmdEnd).await
    }};
}
