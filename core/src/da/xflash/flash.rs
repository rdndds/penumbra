/*
    SPDX-License-Identifier: AGPL-3.0-or-later
    SPDX-FileCopyrightText: 2025 Shomy
*/
use log::{debug, info};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite};

use crate::core::storage::PartitionKind;
use crate::da::DAProtocol;
use crate::da::xflash::XFlash;
use crate::da::xflash::cmds::*;
use crate::error::{Error, Result};
use crate::{le_u32, le_u64};

pub async fn read_flash(
    xflash: &mut XFlash,
    addr: u64,
    size: usize,
    section: PartitionKind,
    progress: &mut (dyn FnMut(usize, usize) + Send),
    writer: &mut (dyn AsyncWrite + Unpin + Send),
) -> Result<()> {
    info!("Reading flash at address {:#X} with size {:#X}", addr, size);

    let storage_type = xflash.get_storage_type().await as u32;
    let partition_type = section.as_u32();

    // Format:
    // Storage Type (EMMC, UFS, NAND) u32
    // PartType u32 (BOOT or USER for EMMC)
    // Address u32
    // Size u32
    // Nand Specific
    //
    // 01000000 u32
    // 08000000 u32
    // 0000000000000000 u64
    // 4400000000000000 u64
    // 0000000000000000000000000000000000000000000000000000000000000000 8u32
    // The payload above is sent when reading PGPT (addr: 0x0, size: 0x44)
    let mut param = [0u8; 56];
    param[0..4].copy_from_slice(&storage_type.to_le_bytes());
    param[4..8].copy_from_slice(&partition_type.to_le_bytes());
    param[8..16].copy_from_slice(&addr.to_le_bytes());
    param[16..24].copy_from_slice(&(size as u64).to_le_bytes());

    xflash.send_cmd(Cmd::ReadData).await?;
    xflash.send(&param).await?;
    status_ok!(xflash);

    xflash.upload_data(size, writer, progress).await?;

    info!("Flash read completed, 0x{:X} bytes read.", size);

    Ok(())
}

pub async fn write_flash(
    xflash: &mut XFlash,
    addr: u64,
    size: usize,
    reader: &mut (dyn AsyncRead + Unpin + Send),
    section: PartitionKind,
    progress: &mut (dyn FnMut(usize, usize) + Send),
) -> Result<()> {
    info!("Writing flash at address {:#X} with size {:#X}", addr, size);

    let storage_type = xflash.get_storage_type().await as u32;
    let partition_type = section.as_u32();

    let mut param = [0u8; 56];
    param[0..4].copy_from_slice(&storage_type.to_le_bytes());
    param[4..8].copy_from_slice(&partition_type.to_le_bytes());
    param[8..16].copy_from_slice(&addr.to_le_bytes());
    param[16..24].copy_from_slice(&(size as u64).to_le_bytes());

    xflash.send_cmd(Cmd::WriteData).await?;
    xflash.send(&param).await?;

    xflash.download_data(size, reader, progress).await?;

    info!("Flash write completed, 0x{:X} bytes written.", size);

    Ok(())
}

pub async fn erase_flash(
    xflash: &mut XFlash,
    addr: u64,
    size: usize,
    section: PartitionKind,
    progress: &mut (dyn FnMut(usize, usize) + Send),
) -> Result<()> {
    info!("Erasing flash at address {:#X} with size {:#X}", addr, size);

    let storage_type = xflash.get_storage_type().await as u32;
    let partition_type = section.as_u32();

    let mut param = [0u8; 56];
    param[0..4].copy_from_slice(&storage_type.to_le_bytes());
    param[4..8].copy_from_slice(&partition_type.to_le_bytes());
    param[8..16].copy_from_slice(&addr.to_le_bytes());
    param[16..24].copy_from_slice(&(size as u64).to_le_bytes());

    xflash.send_cmd(Cmd::Format).await?;
    xflash.send(&param).await?;

    xflash.progress_report(size, progress).await?;

    info!("Flash erase completed.");
    Ok(())
}

pub async fn download(
    xflash: &mut XFlash,
    part_name: String,
    size: usize,
    reader: &mut (dyn AsyncRead + Unpin + Send),
    progress: &mut (dyn FnMut(usize, usize) + Send),
) -> Result<()> {
    // Works like write_flash, but instead of address and size, it takes a partition name
    // and writes the whole data to it.
    // The main difference betwen write_flash and this function is that this one
    // relies on the DA to find the partition by name.
    // Also, this command doesn't support writing only a part of the partition,
    // it will always write the whole partition with the data provided.

    xflash.send_cmd(Cmd::DeviceCtrl).await?;
    xflash.send_cmd(Cmd::StartDlInfo).await?;
    status_ok!(xflash);

    xflash.send_cmd(Cmd::Download).await?;
    xflash.send_data(&[part_name.as_bytes(), &size.to_le_bytes()]).await?;

    info!("Starting download to partition '{}' with size 0x{:X}", part_name, size);

    xflash.download_data(size, reader, progress).await?;

    xflash.send_cmd(Cmd::DeviceCtrl).await?;
    xflash.send_cmd(Cmd::EndDlInfo).await?;
    status_ok!(xflash);

    debug!("Download completed, 0x{:X} bytes sent.", size);

    Ok(())
}

pub async fn upload(
    xflash: &mut XFlash,
    part_name: String,
    writer: &mut (dyn AsyncWrite + Unpin + Send),
    progress: &mut (dyn FnMut(usize, usize) + Send),
) -> Result<()> {
    xflash.send_cmd(Cmd::Upload).await?;
    xflash.send(part_name.as_bytes()).await?;

    let size = {
        let size_data = xflash.read_data().await?;
        status_ok!(xflash);
        if size_data.len() < 8 {
            return Err(Error::proto("Received upload size is too short"));
        }
        le_u64!(size_data, 0) as usize
    };

    info!("Starting readback of partition '{}' with size 0x{:X}", part_name, size);

    xflash.upload_data(size, writer, progress).await?;

    info!("Upload completed, 0x{:X} bytes received.", size);

    Ok(())
}

pub async fn format(
    xflash: &mut XFlash,
    part_name: String,
    progress: &mut (dyn FnMut(usize, usize) + Send),
) -> Result<()> {
    let part = match xflash.dev_info.get_partition(&part_name).await {
        Some(p) => p,
        None => {
            return Err(Error::proto(format!(
                "Partition '{}' not found in partition table",
                part_name
            )));
        }
    };

    xflash.send_cmd(Cmd::FormatPartition).await?;
    // The device starts sending statuses right after sending the partition name,
    // because MTK forgot to put a status write after the command :/
    // so we have to send it manually through the port and not through send()
    let hdr = xflash.generate_header(part_name.as_bytes());
    xflash.conn.write(&hdr).await?;
    xflash.conn.write(part_name.as_bytes()).await?;

    info!("Formatting partition '{}'", part_name);

    xflash.progress_report(part.size, progress).await?;

    info!("Partition '{}' formatted.", part_name);
    Ok(())
}

pub async fn set_rsc_info<F, R>(
    xflash: &mut XFlash,
    part_name: &str,
    size: usize,
    mut reader: R,
    mut progress: F,
) -> Result<()>
where
    R: AsyncRead + Unpin,
    F: FnMut(usize, usize),
{
    // Split in chunks of 256 bytes
    // The payload structure is like this:
    // u64 offset LE (each iteration, it increases by 1)
    // 64 bytes partition name (null-terminated)
    // 256 bytes (data)

    let mut offset = 0u64;
    let mut buffer = vec![0u8; 256];

    loop {
        let mut payload = Vec::new();
        // First byte is 0
        payload.push(0x00);

        let offset_bytes = offset.to_le_bytes();
        payload.extend_from_slice(&offset_bytes[..7]);

        let mut part_name_bytes = vec![0u8; 64];
        let name_bytes = part_name.as_bytes();
        let name_len = name_bytes.len().min(63);
        part_name_bytes[..name_len].copy_from_slice(&name_bytes[..name_len]);
        payload.extend_from_slice(&part_name_bytes);

        let bytes_read = reader.read(&mut buffer).await?;
        if bytes_read == 0 {
            break;
        }

        let chunk = if bytes_read < 256 {
            let mut chunk_buf = vec![0u8; 256];
            chunk_buf[..bytes_read].copy_from_slice(&buffer[..bytes_read]);
            chunk_buf
        } else {
            buffer[..].to_vec()
        };

        payload.extend_from_slice(&chunk);
        assert_eq!(payload.len(), 328);

        xflash.devctrl(Cmd::SetRscInfo, Some(&[&payload])).await?;

        progress(offset as usize * 256 + bytes_read, size);
        offset += 1;
    }

    Ok(())
}

pub async fn get_packet_length(xflash: &mut XFlash) -> Result<(usize, usize)> {
    let packet_length = xflash.devctrl(Cmd::GetPacketLength, None).await?;

    if packet_length.len() < 8 {
        return Err(Error::proto("Received packet length is too short"));
    }

    let write_len = le_u32!(packet_length, 0) as usize;
    let read_len = le_u32!(packet_length, 4) as usize;

    xflash.write_packet_length = Some(write_len);
    xflash.read_packet_length = Some(read_len);

    Ok((write_len, read_len))
}
