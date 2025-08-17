//! 协议模块
//!
//! 实现Shadowsocks和SOCKS5协议的处理逻辑

pub mod address;
pub mod http;
pub mod manager;
pub mod shadowsocks;
pub mod socks5;
pub mod traits;
pub mod vmess;

pub use address::{Address, AddressType};
pub use http::HttpProxy;
pub use shadowsocks::ShadowsocksProtocol;
pub use socks5::{Socks5Response, Socks5Server};
pub use traits::{ProtocolConfig, ProtocolHandler, ProtocolClient, ProtocolFactory, ProtocolRegistry, ProxyConfig, ProtocolType};

use anyhow::Result;
use std::io::{Read, Write};

/// 协议版本常量
pub const SHADOWSOCKS_VERSION: u8 = 1;
pub const SOCKS5_VERSION: u8 = 5;
pub const HTTP_VERSION_1_0: &str = "HTTP/1.0";
pub const HTTP_VERSION_1_1: &str = "HTTP/1.1";

/// SOCKS5认证方法
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Socks5AuthMethod {
    NoAuth = 0x00,
    UserPass = 0x02,
    NoAcceptable = 0xFF,
}

impl From<u8> for Socks5AuthMethod {
    fn from(value: u8) -> Self {
        match value {
            0x00 => Socks5AuthMethod::NoAuth,
            0x02 => Socks5AuthMethod::UserPass,
            _ => Socks5AuthMethod::NoAcceptable,
        }
    }
}

/// SOCKS5命令类型
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Socks5CommandType {
    Connect = 0x01,
    Bind = 0x02,
    UdpAssociate = 0x03,
}

impl From<u8> for Socks5CommandType {
    fn from(value: u8) -> Self {
        match value {
            0x01 => Socks5CommandType::Connect,
            0x02 => Socks5CommandType::Bind,
            0x03 => Socks5CommandType::UdpAssociate,
            _ => Socks5CommandType::Connect, // 默认为连接
        }
    }
}

/// SOCKS5响应状态
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Socks5ResponseCode {
    Success = 0x00,
    GeneralFailure = 0x01,
    ConnectionNotAllowed = 0x02,
    NetworkUnreachable = 0x03,
    HostUnreachable = 0x04,
    ConnectionRefused = 0x05,
    TtlExpired = 0x06,
    CommandNotSupported = 0x07,
    AddressTypeNotSupported = 0x08,
}

/// 读取指定长度的数据
pub fn read_exact(reader: &mut impl Read, buf: &mut [u8]) -> Result<()> {
    reader
        .read_exact(buf)
        .map_err(|e| anyhow::anyhow!("Failed to read exact bytes: {}", e))
}

/// 写入所有数据
pub fn write_all(writer: &mut impl Write, buf: &[u8]) -> Result<()> {
    writer
        .write_all(buf)
        .map_err(|e| anyhow::anyhow!("Failed to write all bytes: {}", e))
}

/// 读取单个字节
pub fn read_u8(reader: &mut impl Read) -> Result<u8> {
    let mut buf = [0u8; 1];
    read_exact(reader, &mut buf)?;
    Ok(buf[0])
}

/// 写入单个字节
pub fn write_u8(writer: &mut impl Write, value: u8) -> Result<()> {
    write_all(writer, &[value])
}

/// 读取16位大端序整数
pub fn read_u16_be(reader: &mut impl Read) -> Result<u16> {
    let mut buf = [0u8; 2];
    read_exact(reader, &mut buf)?;
    Ok(u16::from_be_bytes(buf))
}

/// 写入16位大端序整数
pub fn write_u16_be(writer: &mut impl Write, value: u16) -> Result<()> {
    write_all(writer, &value.to_be_bytes())
}

/// 读取32位大端序整数
pub fn read_u32_be(reader: &mut impl Read) -> Result<u32> {
    let mut buf = [0u8; 4];
    read_exact(reader, &mut buf)?;
    Ok(u32::from_be_bytes(buf))
}

/// 写入32位大端序整数
pub fn write_u32_be(writer: &mut impl Write, value: u32) -> Result<()> {
    write_all(writer, &value.to_be_bytes())
}

/// 读取变长字符串（1字节长度 + 字符串内容）
pub fn read_string(reader: &mut impl Read) -> Result<String> {
    let len = read_u8(reader)? as usize;
    let mut buf = vec![0u8; len];
    read_exact(reader, &mut buf)?;
    String::from_utf8(buf).map_err(|e| anyhow::anyhow!("Invalid UTF-8 string: {}", e))
}

/// 写入变长字符串（1字节长度 + 字符串内容）
pub fn write_string(writer: &mut impl Write, s: &str) -> Result<()> {
    let bytes = s.as_bytes();
    if bytes.len() > 255 {
        return Err(anyhow::anyhow!("String too long: {} bytes", bytes.len()));
    }
    write_u8(writer, bytes.len() as u8)?;
    write_all(writer, bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn test_socks5_auth_method_from_u8() {
        assert_eq!(Socks5AuthMethod::from(0x00), Socks5AuthMethod::NoAuth);
        assert_eq!(Socks5AuthMethod::from(0x02), Socks5AuthMethod::UserPass);
        assert_eq!(Socks5AuthMethod::from(0xFF), Socks5AuthMethod::NoAcceptable);
        assert_eq!(Socks5AuthMethod::from(0x99), Socks5AuthMethod::NoAcceptable);
    }

    #[test]
    fn test_socks5_command_type_from_u8() {
        assert_eq!(Socks5CommandType::from(0x01), Socks5CommandType::Connect);
        assert_eq!(Socks5CommandType::from(0x02), Socks5CommandType::Bind);
        assert_eq!(
            Socks5CommandType::from(0x03),
            Socks5CommandType::UdpAssociate
        );
        assert_eq!(Socks5CommandType::from(0x99), Socks5CommandType::Connect);
    }

    #[test]
    fn test_read_write_u8() {
        let mut buf = Vec::new();
        write_u8(&mut buf, 42).unwrap();

        let mut cursor = Cursor::new(buf);
        let value = read_u8(&mut cursor).unwrap();
        assert_eq!(value, 42);
    }

    #[test]
    fn test_read_write_u16_be() {
        let mut buf = Vec::new();
        write_u16_be(&mut buf, 0x1234).unwrap();

        let mut cursor = Cursor::new(buf);
        let value = read_u16_be(&mut cursor).unwrap();
        assert_eq!(value, 0x1234);
    }

    #[test]
    fn test_read_write_u32_be() {
        let mut buf = Vec::new();
        write_u32_be(&mut buf, 0x12345678).unwrap();

        let mut cursor = Cursor::new(buf);
        let value = read_u32_be(&mut cursor).unwrap();
        assert_eq!(value, 0x12345678);
    }

    #[test]
    fn test_read_write_string() {
        let mut buf = Vec::new();
        write_string(&mut buf, "hello").unwrap();

        let mut cursor = Cursor::new(buf);
        let value = read_string(&mut cursor).unwrap();
        assert_eq!(value, "hello");
    }

    #[test]
    fn test_write_string_too_long() {
        let mut buf = Vec::new();
        let long_string = "a".repeat(256);
        assert!(write_string(&mut buf, &long_string).is_err());
    }

    #[test]
    fn test_read_exact_insufficient_data() {
        let data = vec![1, 2, 3];
        let mut cursor = Cursor::new(data);
        let mut buf = [0u8; 5];
        assert!(read_exact(&mut cursor, &mut buf).is_err());
    }
}
