//! Shadowsocks协议实现
//!
//! 实现Shadowsocks协议的编码和解码逻辑

use crate::crypto::CryptoContext;
use crate::protocol::Address;
use anyhow::{Result, anyhow};
use bytes::BytesMut;
use std::io;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Shadowsocks协议处理器
#[derive(Clone)]
pub struct ShadowsocksProtocol {
    crypto: CryptoContext,
}

impl ShadowsocksProtocol {
    /// 创建新的协议处理器
    pub fn new(crypto: CryptoContext) -> Self {
        Self { crypto }
    }

    /// 编码请求数据
    ///
    /// 格式: [地址][数据]
    pub fn encode_request(&mut self, address: &Address, data: &[u8]) -> Result<Vec<u8>> {
        let mut buffer = Vec::new();

        // 序列化地址
        address.write_to(&mut buffer)?;

        // 添加数据
        buffer.extend_from_slice(data);

        // 加密整个数据包
        self.crypto.encrypt_payload(&buffer)
    }

    /// 解码请求数据
    ///
    /// 返回 (地址, 数据)
    pub fn decode_request(&mut self, encrypted_data: &[u8]) -> Result<(Address, Vec<u8>)> {
        // 解密数据
        let decrypted = self.crypto.decrypt_payload(encrypted_data)?;

        let mut cursor = io::Cursor::new(decrypted);

        // 解析地址
        let address = Address::read_from(&mut cursor)?;

        // 剩余数据
        let pos = cursor.position() as usize;
        let remaining_data = cursor.into_inner();
        let data = remaining_data[pos..].to_vec();

        Ok((address, data))
    }

    /// 编码响应数据
    pub fn encode_response(&mut self, data: &[u8]) -> Result<Vec<u8>> {
        self.crypto.encrypt_payload(data)
    }

    /// 解码响应数据
    pub fn decode_response(&mut self, encrypted_data: &[u8]) -> Result<Vec<u8>> {
        self.crypto.decrypt_payload(encrypted_data)
    }

    /// 从流中读取并解密数据
    pub async fn read_encrypted<R>(&mut self, reader: &mut R, buffer: &mut [u8]) -> Result<usize>
    where
        R: AsyncRead + Unpin,
    {
        // 读取加密数据长度（2字节）
        let mut len_buf = [0u8; 2];
        reader
            .read_exact(&mut len_buf)
            .await
            .map_err(|e| anyhow!("Failed to read length: {}", e))?;

        let encrypted_len = u16::from_be_bytes(len_buf) as usize;

        if encrypted_len == 0 {
            return Ok(0);
        }

        // 读取加密数据
        let mut encrypted_buf = vec![0u8; encrypted_len];
        reader
            .read_exact(&mut encrypted_buf)
            .await
            .map_err(|e| anyhow!("Failed to read encrypted data: {}", e))?;

        // 解密数据
        let decrypted = self.crypto.decrypt_payload(&encrypted_buf)?;

        // 复制到输出缓冲区
        let copy_len = std::cmp::min(decrypted.len(), buffer.len());
        buffer[..copy_len].copy_from_slice(&decrypted[..copy_len]);

        Ok(copy_len)
    }

    /// 加密并写入数据到流
    pub async fn write_encrypted<W>(&mut self, writer: &mut W, data: &[u8]) -> Result<()>
    where
        W: AsyncWrite + Unpin,
    {
        if data.is_empty() {
            return Ok(());
        }

        // 加密数据
        let encrypted = self.crypto.encrypt_payload(data)?;

        // 写入长度（2字节）
        let len = encrypted.len() as u16;
        writer
            .write_all(&len.to_be_bytes())
            .await
            .map_err(|e| anyhow!("Failed to write length: {}", e))?;

        // 写入加密数据
        writer
            .write_all(&encrypted)
            .await
            .map_err(|e| anyhow!("Failed to write encrypted data: {}", e))?;

        Ok(())
    }

    /// 处理TCP连接的初始握手
    ///
    /// 客户端发送第一个请求包含目标地址
    pub async fn handle_tcp_handshake<R>(&mut self, reader: &mut R) -> Result<Address>
    where
        R: AsyncRead + Unpin,
    {
        // 读取第一个数据包
        let mut buffer = vec![0u8; 4096];
        let n = self.read_encrypted(reader, &mut buffer).await?;

        if n == 0 {
            return Err(anyhow!("Empty handshake packet"));
        }

        // 解析地址（第一个包应该只包含地址信息）
        let mut cursor = io::Cursor::new(&buffer[..n]);
        let address = Address::read_from(&mut cursor)?;

        Ok(address)
    }

    /// 创建UDP数据包
    ///
    /// UDP格式: [地址][数据]
    pub fn create_udp_packet(&mut self, address: &Address, data: &[u8]) -> Result<Vec<u8>> {
        let mut buffer = BytesMut::new();

        // 序列化地址
        let mut temp_buf = Vec::new();
        address.write_to(&mut temp_buf)?;
        buffer.extend_from_slice(&temp_buf);

        // 添加数据
        buffer.extend_from_slice(data);

        // 加密整个数据包
        self.crypto.encrypt_payload(&buffer)
    }

    /// 解析UDP数据包
    ///
    /// 返回 (地址, 数据)
    pub fn parse_udp_packet(&mut self, encrypted_data: &[u8]) -> Result<(Address, Vec<u8>)> {
        // 解密数据
        let decrypted = self.crypto.decrypt_payload(encrypted_data)?;

        let mut cursor = io::Cursor::new(decrypted);

        // 解析地址
        let address = Address::read_from(&mut cursor)?;

        // 剩余数据
        let pos = cursor.position() as usize;
        let remaining_data = cursor.into_inner();
        let data = remaining_data[pos..].to_vec();

        Ok((address, data))
    }

    /// 获取加密上下文的引用
    pub fn crypto(&self) -> &CryptoContext {
        &self.crypto
    }

    /// 获取加密上下文的可变引用
    pub fn crypto_mut(&mut self) -> &mut CryptoContext {
        &mut self.crypto
    }

    /// 重置加密上下文（用于新连接）
    pub fn reset_crypto(&mut self) {
        self.crypto.reset_nonce();
    }
}

/// Shadowsocks数据包类型
#[derive(Debug, Clone, PartialEq)]
pub enum PacketType {
    /// TCP连接请求
    TcpConnect,
    /// TCP数据传输
    TcpData,
    /// UDP数据包
    UdpData,
}

/// Shadowsocks数据包
#[derive(Debug, Clone)]
pub struct ShadowsocksPacket {
    /// 数据包类型
    pub packet_type: PacketType,
    /// 目标地址（仅对连接请求有效）
    pub address: Option<Address>,
    /// 数据载荷
    pub data: Vec<u8>,
}

impl ShadowsocksPacket {
    /// 创建TCP连接请求包
    pub fn tcp_connect(address: Address) -> Self {
        Self {
            packet_type: PacketType::TcpConnect,
            address: Some(address),
            data: Vec::new(),
        }
    }

    /// 创建TCP数据包
    pub fn tcp_data(data: Vec<u8>) -> Self {
        Self {
            packet_type: PacketType::TcpData,
            address: None,
            data,
        }
    }

    /// 创建UDP数据包
    pub fn udp_data(address: Address, data: Vec<u8>) -> Self {
        Self {
            packet_type: PacketType::UdpData,
            address: Some(address),
            data,
        }
    }

    /// 序列化数据包
    pub fn serialize(&self, crypto: &mut CryptoContext) -> Result<Vec<u8>> {
        let mut buffer = BytesMut::new();

        match self.packet_type {
            PacketType::TcpConnect => {
                if let Some(ref address) = self.address {
                    let mut temp_buf = Vec::new();
                    address.write_to(&mut temp_buf)?;
                    buffer.extend_from_slice(&temp_buf);
                } else {
                    return Err(anyhow!("TCP connect packet must have address"));
                }
            }
            PacketType::TcpData => {
                buffer.extend_from_slice(&self.data);
            }
            PacketType::UdpData => {
                if let Some(ref address) = self.address {
                    let mut temp_buf = Vec::new();
                    address.write_to(&mut temp_buf)?;
                    buffer.extend_from_slice(&temp_buf);
                    buffer.extend_from_slice(&self.data);
                } else {
                    return Err(anyhow!("UDP packet must have address"));
                }
            }
        }

        crypto.encrypt_payload(&buffer)
    }

    /// 反序列化数据包
    pub fn deserialize(
        encrypted_data: &[u8],
        packet_type: PacketType,
        crypto: &mut CryptoContext,
    ) -> Result<Self> {
        let decrypted = crypto.decrypt_payload(encrypted_data)?;

        match packet_type {
            PacketType::TcpConnect => {
                let mut cursor = io::Cursor::new(decrypted);
                let address = Address::read_from(&mut cursor)?;
                Ok(Self::tcp_connect(address))
            }
            PacketType::TcpData => Ok(Self::tcp_data(decrypted)),
            PacketType::UdpData => {
                let mut cursor = io::Cursor::new(decrypted);
                let address = Address::read_from(&mut cursor)?;

                let pos = cursor.position() as usize;
                let remaining_data = cursor.into_inner();
                let data = remaining_data[pos..].to_vec();

                Ok(Self::udp_data(address, data))
            }
        }
    }
}

/// 协议版本信息
pub const SHADOWSOCKS_VERSION: u8 = 1;

/// 最大数据包大小
pub const MAX_PACKET_SIZE: usize = 65536;

/// 最小数据包大小
pub const MIN_PACKET_SIZE: usize = 1;

/// 地址头部最大长度
pub const MAX_ADDRESS_LENGTH: usize = 259; // 1 + 1 + 255 + 2

/// 验证数据包大小
pub fn validate_packet_size(size: usize) -> Result<()> {
    if size < MIN_PACKET_SIZE {
        return Err(anyhow!("Packet too small: {} bytes", size));
    }
    if size > MAX_PACKET_SIZE {
        return Err(anyhow!("Packet too large: {} bytes", size));
    }
    Ok(())
}

/// 计算数据包开销
pub fn calculate_packet_overhead(address: &Address, crypto: &CryptoContext) -> usize {
    let address_len = address.serialized_len();
    let crypto_overhead = crypto.tag_len() + crypto.nonce_len();
    address_len + crypto_overhead
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use super::*;
    use crate::crypto::{Method, derive_key};

    fn create_test_crypto() -> CryptoContext {
        let method = Method::Aes128Gcm;
        let password = "test_password".to_string();
        let key = derive_key(password.as_str(), method.key_len());

        let key = String::from_utf8_lossy(key.as_ref());

        CryptoContext::new(method.as_str(), key.as_ref()).unwrap()
    }

    #[test]
    fn test_encode_decode_request() {
        let mut protocol = ShadowsocksProtocol::new(create_test_crypto());

        let address = Address::from_str("example.com:80").unwrap();
        let data = b"GET / HTTP/1.1\r\n\r\n";

        // 编码
        let encoded = protocol.encode_request(&address, data).unwrap();

        // 解码
        let (decoded_address, decoded_data) = protocol.decode_request(&encoded).unwrap();

        assert_eq!(address, decoded_address);
        assert_eq!(data.to_vec(), decoded_data);
    }

    #[test]
    fn test_encode_decode_response() {
        let mut protocol = ShadowsocksProtocol::new(create_test_crypto());

        let data = b"HTTP/1.1 200 OK\r\n\r\n";

        // 编码
        let encoded = protocol.encode_response(data).unwrap();

        // 解码
        let decoded = protocol.decode_response(&encoded).unwrap();

        assert_eq!(data.to_vec(), decoded);
    }

    #[test]
    fn test_create_parse_udp_packet() {
        let mut protocol = ShadowsocksProtocol::new(create_test_crypto());

        let address = Address::from_str("192.168.1.1:53").unwrap();
        let data = b"DNS query data";

        // 创建UDP数据包
        let packet = protocol.create_udp_packet(&address, data).unwrap();

        // 解析UDP数据包
        let (parsed_address, parsed_data) = protocol.parse_udp_packet(&packet).unwrap();

        assert_eq!(address, parsed_address);
        assert_eq!(data.to_vec(), parsed_data);
    }

    #[test]
    fn test_shadowsocks_packet_tcp_connect() {
        let address = Address::from_str("example.com:443").unwrap();
        let packet = ShadowsocksPacket::tcp_connect(address.clone());

        assert_eq!(packet.packet_type, PacketType::TcpConnect);
        assert_eq!(packet.address, Some(address));
        assert!(packet.data.is_empty());
    }

    #[test]
    fn test_shadowsocks_packet_tcp_data() {
        let data = b"Hello, World!".to_vec();
        let packet = ShadowsocksPacket::tcp_data(data.clone());

        assert_eq!(packet.packet_type, PacketType::TcpData);
        assert_eq!(packet.address, None);
        assert_eq!(packet.data, data);
    }

    #[test]
    fn test_shadowsocks_packet_udp_data() {
        let address = Address::from_str("8.8.8.8:53").unwrap();
        let data = b"DNS query".to_vec();
        let packet = ShadowsocksPacket::udp_data(address.clone(), data.clone());

        assert_eq!(packet.packet_type, PacketType::UdpData);
        assert_eq!(packet.address, Some(address));
        assert_eq!(packet.data, data);
    }

    #[test]
    fn test_packet_serialize_deserialize() {
        let mut crypto = create_test_crypto();

        // 测试TCP连接包
        let address = Address::from_str("example.com:80").unwrap();
        let tcp_packet = ShadowsocksPacket::tcp_connect(address.clone());

        let serialized = tcp_packet.serialize(&mut crypto).unwrap();
        let deserialized =
            ShadowsocksPacket::deserialize(&serialized, PacketType::TcpConnect, &mut crypto)
                .unwrap();

        assert_eq!(tcp_packet.packet_type, deserialized.packet_type);
        assert_eq!(tcp_packet.address, deserialized.address);

        // 测试UDP数据包
        let data = b"test data".to_vec();
        let udp_packet = ShadowsocksPacket::udp_data(address.clone(), data.clone());

        let serialized = udp_packet.serialize(&mut crypto).unwrap();
        let deserialized =
            ShadowsocksPacket::deserialize(&serialized, PacketType::UdpData, &mut crypto).unwrap();

        assert_eq!(udp_packet.packet_type, deserialized.packet_type);
        assert_eq!(udp_packet.address, deserialized.address);
        assert_eq!(udp_packet.data, deserialized.data);
    }

    #[test]
    fn test_validate_packet_size() {
        assert!(validate_packet_size(MIN_PACKET_SIZE).is_ok());
        assert!(validate_packet_size(MAX_PACKET_SIZE).is_ok());
        assert!(validate_packet_size(1024).is_ok());

        assert!(validate_packet_size(0).is_err());
        assert!(validate_packet_size(MAX_PACKET_SIZE + 1).is_err());
    }

    #[test]
    fn test_calculate_packet_overhead() {
        let crypto = create_test_crypto();
        let address = Address::from_str("example.com:80").unwrap();

        let overhead = calculate_packet_overhead(&address, &crypto);

        // 应该包含地址长度 + 加密开销
        let expected = address.serialized_len() + crypto.tag_len() + crypto.nonce_len();
        assert_eq!(overhead, expected);
    }

    #[test]
    fn test_protocol_reset_crypto() {
        let mut protocol = ShadowsocksProtocol::new(create_test_crypto());

        // 使用一次加密
        let data = b"test data";
        let _ = protocol.encode_response(data).unwrap();

        // 重置加密上下文
        protocol.reset_crypto();

        // 应该能够正常工作
        let encoded = protocol.encode_response(data).unwrap();
        let decoded = protocol.decode_response(&encoded).unwrap();
        assert_eq!(data.to_vec(), decoded);
    }

    #[test]
    fn test_empty_data_handling() {
        let mut protocol = ShadowsocksProtocol::new(create_test_crypto());

        let address = Address::from_str("example.com:80").unwrap();
        let empty_data = b"";

        // 编码空数据
        let encoded = protocol.encode_request(&address, empty_data).unwrap();

        // 解码应该成功
        let (decoded_address, decoded_data) = protocol.decode_request(&encoded).unwrap();

        assert_eq!(address, decoded_address);
        assert_eq!(empty_data.to_vec(), decoded_data);
    }
}
