/*
    SPDX-License-Identifier: AGPL-3.0-or-later
    SPDX-FileCopyrightText: 2025 Shomy
*/
use tokio::io::{AsyncRead, AsyncWrite};

use crate::da::Xml;
use crate::da::xml::cmds::{FileSystemOp, ReadPartition, WritePartition, XmlCmdLifetime};
use crate::error::Result;

pub async fn upload<F, W>(
    xml: &mut Xml,
    part_name: String,
    mut writer: W,
    mut progress: F,
) -> Result<()>
where
    W: AsyncWrite + Unpin,
    F: FnMut(usize, usize) + Send,
{
    xmlcmd!(xml, ReadPartition, &part_name, &part_name)?;

    xml.upload_file(&mut writer, &mut progress).await?;
    xml.lifetime_ack(XmlCmdLifetime::CmdEnd).await?;

    Ok(())
}

pub async fn download<F, R>(
    xml: &mut Xml,
    part_name: String,
    size: usize,
    mut reader: R,
    mut progress: F,
) -> Result<()>
where
    R: AsyncRead + Unpin,
    F: FnMut(usize, usize) + Send,
{
    xmlcmd!(xml, WritePartition, &part_name, &part_name)?;
    xml.progress_report().await?;

    // Enabled only on DA with security on?
    if xml.dev_info.sbc_enabled().await {
        xml.file_system_op(FileSystemOp::Exists).await?;
        xml.file_system_op(FileSystemOp::Exists).await?;
    }

    xml.download_file(size, &mut reader, &mut progress).await?;
    xml.lifetime_ack(XmlCmdLifetime::CmdEnd).await?;

    Ok(())
}
