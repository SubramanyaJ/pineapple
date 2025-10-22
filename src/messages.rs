/**
 * messages.rs
 */
use anyhow::{Context, Result};
use std::fs;
use std::path::Path;

#[derive(Debug)]
pub enum MessageType {
    Text(String),
    File { filename: String, data: Vec<u8> },
}

/// Parse input from user - detect file transfer command with !
pub fn parse_input(input: &str) -> Result<MessageType> {
    if input.starts_with('!') {
        let path = input[1..].trim();
        let filename = Path::new(path)
            .file_name()
            .and_then(|n| n.to_str())
            .context("Invalid filename")?
            .to_string();
        
        let data = fs::read(path)
            .context(format!("Failed to read file: {}", path))?;
        
        Ok(MessageType::File { filename, data })
    } else {
        Ok(MessageType::Text(input.to_string()))
    }
}

/// Serialize message to bytes with type tag
pub fn serialize_message(msg_type: &MessageType) -> Vec<u8> {
    match msg_type {
        MessageType::Text(text) => {
            let mut buf = vec![0u8]; // Type byte: 0 = text
            buf.extend_from_slice(text.as_bytes());
            buf
        }
        MessageType::File { filename, data } => {
            let mut buf = vec![1u8]; // Type byte: 1 = file
            let name_bytes = filename.as_bytes();
            buf.extend_from_slice(&(name_bytes.len() as u32).to_le_bytes());
            buf.extend_from_slice(name_bytes);
            buf.extend_from_slice(data);
            buf
        }
    }
}

/// Deserialize message from bytes
pub fn deserialize_message(buf: &[u8]) -> Result<MessageType> {
    if buf.is_empty() {
        anyhow::bail!("Empty message buffer");
    }
    
    match buf[0] {
        0 => {
            // Text message
            Ok(MessageType::Text(
                String::from_utf8(buf[1..].to_vec())
                    .context("Invalid UTF-8 in text message")?
            ))
        }
        1 => {
            // File message
            if buf.len() < 5 {
                anyhow::bail!("File message too short");
            }
            let name_len = u32::from_le_bytes([buf[1], buf[2], buf[3], buf[4]]) as usize;
            if buf.len() < 5 + name_len {
                anyhow::bail!("Invalid file message format");
            }
            let filename = String::from_utf8(buf[5..5+name_len].to_vec())
                .context("Invalid UTF-8 in filename")?;
            let data = buf[5+name_len..].to_vec();
            Ok(MessageType::File { filename, data })
        }
        _ => anyhow::bail!("Unknown message type: {}", buf[0]),
    }
}

