/*
    SPDX-License-Identifier: AGPL-3.0-or-later
    SPDX-FileCopyrightText: 2025 Shomy
*/
use log::{debug, info};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::core::storage::PartitionKind;
use crate::da::DAProtocol;
use crate::da::xflash::XFlash;
use crate::da::xflash::cmds::*;
use crate::error::{Error, Result};

pub async fn read_flash<F, W>(
    xflash: &mut XFlash,
    addr: u64,
    size: usize,
    section: PartitionKind,
    mut progress: F,
    mut writer: W,
) -> Result<()>
where
    F: FnMut(usize, usize),
    W: AsyncWrite + Unpin,
{
    info!("Reading flash at address {:#X} with size {:#X}", addr, size);

    let storage_type = xflash.get_storage_type().await as u32;

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
    let partition_type = section.as_u32();
    let nand_ext = [0u32; 8]; // Nand specific, set to 0 for non-nand storage types

    let mut param = Vec::new();
    param.extend_from_slice(&storage_type.to_le_bytes());
    param.extend_from_slice(&partition_type.to_le_bytes());
    param.extend_from_slice(&addr.to_le_bytes());
    param.extend_from_slice(&(size as u64).to_le_bytes());
    // Which basically means: append it! Improvements are welcome.
    param.extend_from_slice(&nand_ext.iter().flat_map(|x| x.to_le_bytes()).collect::<Vec<u8>>());

    xflash.send_cmd(Cmd::ReadData).await?;
    xflash.send(&param).await?;
    status_ok!(xflash);

    let mut bytes_read = 0;

    // Read chunk, send acknowledgment, status, repeat until profit
    progress(0, size);
    loop {
        let chunk = xflash.read_data().await?;
        if chunk.is_empty() {
            debug!("No data received, breaking.");
            break;
        }

        writer.write_all(&chunk).await?;
        bytes_read += chunk.len();

        let ack_payload = [0u8; 4];

        xflash.send(&ack_payload).await?;

        debug!("Chunk of {} bytes read.", chunk.len());
        progress(bytes_read, size);

        if bytes_read >= size {
            debug!("Requested size read. Breaking.");
            break;
        }

        debug!("Read {:X}/{:X} bytes...", bytes_read, size);
    }

    info!("Flash read completed, 0x{:X} bytes read.", bytes_read);

    Ok(())
}

pub async fn write_flash<F, R>(
    xflash: &mut XFlash,
    addr: u64,
    size: usize,
    mut reader: R,
    section: PartitionKind,
    mut progress: F,
) -> Result<()>
where
    R: AsyncRead + Unpin,
    F: FnMut(usize, usize),
{
    info!("Writing flash at address {:#X} with size {:#X}", addr, size);

    // Note to self:
    // Next time, don't put this after Cmd::WriteData,
    // or don't expect it to work :/
    let chunk_size = get_write_packet_length(xflash).await?;
    debug!("Using chunk size of {} bytes", chunk_size);

    let storage_type = xflash.get_storage_type().await as u32;

    let partition_type = section.as_u32();
    let nand_ext = [0u32; 8];
    let mut param = Vec::new();
    param.extend_from_slice(&storage_type.to_le_bytes());
    param.extend_from_slice(&partition_type.to_le_bytes());
    param.extend_from_slice(&addr.to_le_bytes());
    param.extend_from_slice(&(size as u64).to_le_bytes());
    param.extend_from_slice(&nand_ext.iter().flat_map(|x| x.to_le_bytes()).collect::<Vec<u8>>());

    xflash.send_cmd(Cmd::WriteData).await?;
    xflash.send(&param).await?;

    let mut buffer = vec![0u8; chunk_size];
    let mut bytes_written = 0;

    debug!("Starting to write data in chunks of {} bytes...", chunk_size);
    progress(0, size);
    loop {
        if bytes_written >= size {
            break;
        }

        // It is mandatory to make data size the same as size, or we will be leaving
        // older data in the partition. Usually, this is not an issue for partitions
        // with an header, like LK (which stores the start and length of the lk image),
        // but for other partitions, this might make the partition unusable.
        // This issue only arises when flashing stuff that is not coming from a dump made
        // with read_flash() or any other tool like mtkclient.
        let remaining = size - bytes_written;
        let to_read = remaining.min(chunk_size);

        let bytes_read = reader.read(&mut buffer[..to_read]).await?;
        let chunk = if bytes_read == 0 {
            &buffer[..to_read]
        } else if bytes_read < to_read {
            buffer[bytes_read..to_read].fill(0);
            &buffer[..to_read]
        } else {
            &buffer[..to_read]
        };

        // DA expects a checksum of the data chunk before the actual data
        // The actual checksum is a additive 16-bit checksum (Good job MTK!!)
        // For whoever is reading this code and has no clue what this is doing:
        // Just sum all bytes then AND with 0xFFFF :D!!!
        let checksum = chunk.iter().fold(0u32, |total, &byte| total + byte as u32) & 0xFFFF;
        xflash.send_data(&[&0u32.to_le_bytes(), &checksum.to_le_bytes(), chunk]).await?;

        bytes_written += chunk.len();
        progress(bytes_written, size);
        debug!("Written {}/{} bytes...", bytes_written, size);
    }

    status_ok!(xflash);
    info!("Flash write completed, 0x{:X} bytes written.", bytes_written);

    Ok(())
}

pub async fn erase_flash<F>(
    xflash: &mut XFlash,
    addr: u64,
    size: usize,
    section: PartitionKind,
    mut progress: F,
) -> Result<()>
where
    F: FnMut(usize, usize),
{
    info!("Erasing flash at address {:#X} with size {:#X}", addr, size);
    let storage_type = xflash.get_storage_type().await as u32;

    let partition_type = section.as_u32();
    let nand_ext = [0u32; 8];
    let mut param = Vec::new();
    param.extend_from_slice(&storage_type.to_le_bytes());
    param.extend_from_slice(&partition_type.to_le_bytes());
    param.extend_from_slice(&addr.to_le_bytes());
    param.extend_from_slice(&(size as u64).to_le_bytes());
    param.extend_from_slice(&nand_ext.iter().flat_map(|x| x.to_le_bytes()).collect::<Vec<u8>>());

    xflash.send_cmd(Cmd::Format).await?;
    xflash.send(&param).await?;

    progress(0, size);
    let mut status = vec![0u8; 4];
    loop {
        status = xflash.read_data().await?;
        if u32::from_le_bytes(status.try_into().unwrap()) == 0x40040005 {
            progress(size, size);
            break;
        }

        status = xflash.read_data().await?;
        let progress_percent = u32::from_le_bytes(status.try_into().unwrap());
        let ack = [0u8; 4];
        // The device doesn't send statuses during erase, so we have to send
        // an acknowledgment manually through the port and not through send()
        let hdr = xflash.generate_header(&ack);
        xflash.conn.port.write_all(&hdr).await?;
        xflash.conn.port.write_all(&ack).await?;

        let progress_bytes = (progress_percent as usize * size) / 100;
        progress(progress_bytes, size);
    }

    info!("Flash erase completed.");
    Ok(())
}

pub async fn download<F, R>(
    xflash: &mut XFlash,
    part_name: String,
    size: usize,
    mut reader: R,
    mut progress: F,
) -> Result<()>
where
    R: AsyncRead + Unpin,
    F: FnMut(usize, usize),
{
    // Works like write_flash, but instead of address and size, it takes a partition name
    // and writes the whole data to it.
    // The main difference betwen write_flash and this function is that this one
    // relies on the DA to find the partition by name.
    // Also, this command doesn't support writing only a part of the partition,
    // it will always write the whole partition with the data provided.
    let chunk_size = get_write_packet_length(xflash).await?;

    xflash.send_cmd(Cmd::DeviceCtrl).await?;
    xflash.send_cmd(Cmd::StartDlInfo).await?;
    status_ok!(xflash);

    xflash.send_cmd(Cmd::Download).await?;
    xflash.send_data(&[part_name.as_bytes(), &size.to_le_bytes()]).await?;

    let mut buffer = vec![0u8; chunk_size];
    let mut bytes_written = 0;

    info!("Starting download to partition '{}' with size 0x{:X}", part_name, size);

    progress(0, size);
    loop {
        let remaining = size - bytes_written;
        let to_read = remaining.min(chunk_size);

        let bytes_read = reader.read(&mut buffer[..to_read]).await?;
        if bytes_read == 0 {
            break;
        }

        let chunk = &buffer[..bytes_read];

        let checksum = chunk.iter().fold(0u32, |total, &byte| total + byte as u32) & 0xFFFF;
        xflash.send_data(&[&0u32.to_le_bytes(), &checksum.to_le_bytes(), chunk]).await?;

        bytes_written += bytes_read;

        progress(bytes_written, size);
    }

    status_ok!(xflash);

    xflash.send_cmd(Cmd::DeviceCtrl).await?;
    xflash.send_cmd(Cmd::EndDlInfo).await?;
    status_ok!(xflash);

    debug!("Download completed, 0x{:X} bytes sent.", size);

    Ok(())
}

pub async fn upload<F, W>(
    xflash: &mut XFlash,
    part_name: String,
    mut writer: W,
    mut progress: F,
) -> Result<()>
where
    W: AsyncWrite + Unpin,
    F: FnMut(usize, usize),
{
    xflash.send_cmd(Cmd::Upload).await?;
    xflash.send(part_name.as_bytes()).await?;

    let size = {
        let size_data = xflash.read_data().await?;
        status_ok!(xflash);
        if size_data.len() < 8 {
            return Err(Error::proto("Received upload size is too short"));
        }
        let mut size_buf = [0u8; 8];
        size_buf.copy_from_slice(&size_data[0..8]);
        u64::from_le_bytes(size_buf) as usize
    };

    info!("Starting readback of partition '{}' with size 0x{:X}", part_name, size);

    let mut bytes_read = 0;
    progress(0, size);
    loop {
        let chunk = xflash.read_data().await?;
        if chunk.is_empty() {
            debug!("No data received, breaking.");
            break;
        }

        writer.write_all(&chunk).await?;
        bytes_read += chunk.len();

        xflash.send(&[0u8; 4]).await?;

        progress(bytes_read, size);

        if bytes_read >= size {
            debug!("Requested size read. Breaking.");
            break;
        }
    }
    info!("Upload completed, 0x{:X} bytes received.", size);

    Ok(())
}

pub async fn format<F>(xflash: &mut XFlash, part_name: String, mut progress: F) -> Result<()>
where
    F: FnMut(usize, usize),
{
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
    xflash.conn.port.write_all(&hdr).await?;
    xflash.conn.port.write_all(part_name.as_bytes()).await?;

    info!("Formatting partition '{}'", part_name);

    progress(0, part.size);
    let mut status = vec![0u8; 4];
    loop {
        status = xflash.read_data().await?;
        if u32::from_le_bytes(status.try_into().unwrap()) == 0x40040005 {
            progress(part.size, part.size);
            break;
        }

        status = xflash.read_data().await?;
        let progress_percent = u32::from_le_bytes(status.try_into().unwrap());
        let ack = [0u8; 4];
        // The device doesn't send statuses during erase, so we have to send
        // an acknowledgment manually through the port and not through send()
        let hdr = xflash.generate_header(&ack);
        xflash.conn.port.write_all(&hdr).await?;
        xflash.conn.port.write_all(&ack).await?;

        let progress_bytes = (progress_percent as usize * part.size) / 100;
        progress(progress_bytes, part.size);
    }

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

    // TODO: Find a better way of doing this, currently, this is bad
    let mut write_buf = [0u8; 4];
    let mut read_buf = [0u8; 4];

    write_buf.copy_from_slice(&packet_length[0..4]);
    read_buf.copy_from_slice(&packet_length[4..8]);

    let write_len = u32::from_le_bytes(write_buf) as usize;
    let read_len = u32::from_le_bytes(read_buf) as usize;

    xflash.write_packet_length = Some(write_len);
    xflash.read_packet_length = Some(read_len);

    Ok((write_len, read_len))
}

pub async fn get_write_packet_length(xflash: &mut XFlash) -> Result<usize> {
    if xflash.write_packet_length.is_some() {
        return Ok(xflash.write_packet_length.unwrap());
    }

    let (write_len, _) = get_packet_length(xflash).await?;
    Ok(write_len)
}

pub async fn _get_read_packet_length(xflash: &mut XFlash) -> Result<usize> {
    if xflash.read_packet_length.is_some() {
        return Ok(xflash.read_packet_length.unwrap());
    }

    let (_, read_len) = get_packet_length(xflash).await?;
    Ok(read_len)
}
