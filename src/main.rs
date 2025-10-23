/**
 * main.rs
 */

use anyhow::{Result, Context};
use pineapple::{pqxdh, Session, network, messages};
use std::env;
use std::net::{TcpListener, TcpStream};
use std::io::{self, BufRead, Write};
use std::sync::{Arc, Mutex};
use std::thread;

fn main() -> Result<()> {
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        eprintln!("Usage:");
        eprintln!("  As listener: {} listen <port>", args[0]);
        eprintln!("  As client: {} connect <ip:port>", args[0]);
        std::process::exit(1);
    }

    match args[1].as_str() {
        "listen" => {
            if args.len() < 3 {
                eprintln!("Usage: {} listen <port>", args[0]);
                std::process::exit(1);
            }
            let port = &args[2];
            run_alice(port)?;
        }
        "connect" => {
            if args.len() < 3 {
                eprintln!("Usage: {} connect <ip:port>", args[0]);
                std::process::exit(1);
            }
            let address = &args[2];
            run_bob(address)?;
        }
        _ => {
            eprintln!("Invalid mode. Use 'listen' or 'connect'");
            std::process::exit(1);
        }
    }

    Ok(())
}

fn run_alice(port: &str) -> Result<()> {
    println!("pineapple");
    println!("Waiting for connection on port {}...", port);

    let listener = TcpListener::bind(format!("0.0.0.0:{}", port))
        .context("Failed to bind to port")?;

    let (mut stream, addr) = listener.accept()
        .context("Failed to accept connection")?;

    println!("Incoming connection from {}", addr);
    println!("Accept? (yes/no)");

    let mut input = String::new();
    io::stdin().read_line(&mut input)?;

    if !input.trim().eq_ignore_ascii_case("yes") {
        println!("Connection rejected.");
        return Ok(());
    }

    println!("Connection accepted!");
    println!("Performing handshake...\n");

    // Generate Alice's keys
    let alice = pqxdh::User::new();

    // Send Alice's public keys to Bob
    send_public_keys(&mut stream, &alice)?;

    // Receive Bob's public keys
    let mut bob = receive_public_keys(&mut stream)?;

    // Complete handshake: Alice initiates PQXDH
    let (session, init_message) = Session::new_initiator(&alice, &mut bob)?;

    // Send init message to Bob
    network::send_message(&mut stream, &network::serialize_pqxdh_init_message(&init_message))?;

    println!("Session established!\n");
    println!("Type your message and press Enter.");
    println!("To send a file, type: !/path/to/file.txt");
    println!("Press Ctrl+C to exit.\n");

    // Start chat
    chat_loop(session, stream)?;

    Ok(())
}

fn run_bob(address: &str) -> Result<()> {
    println!("pineapple");
    println!("Connecting to {}...", address);

    let mut stream = TcpStream::connect(address)
        .context("Failed to connect to peer")?;

    println!("Connected!");
    println!("Performing handshake...\n");

    // Generate Bob's keys
    let mut bob = pqxdh::User::new();

    // Receive Alice's public keys
    let _alice = receive_public_keys(&mut stream)?;

    // Send Bob's public keys to Alice
    send_public_keys(&mut stream, &bob)?;

    // Receive init message from Alice
    let init_message_data = network::receive_message(&mut stream)?;
    let init_message = network::deserialize_pqxdh_init_message(&init_message_data)?;

    // Complete handshake: Bob responds to PQXDH
    let session = Session::new_responder(&mut bob, &init_message)?;

    println!("Session established!\n");
    println!("Type your message and press Enter.");
    println!("To send a file, type: !/path/to/file.txt");
    println!("Press Ctrl+C to exit.\n");

    // Start chat
    chat_loop(session, stream)?;

    Ok(())
}

fn send_public_keys(stream: &mut TcpStream, user: &pqxdh::User) -> Result<()> {
    let bundle = network::serialize_prekey_bundle(user);
    network::send_message(stream, &bundle)?;
    Ok(())
}

fn receive_public_keys(stream: &mut TcpStream) -> Result<pqxdh::User> {
    let bundle_data = network::receive_message(stream)?;
    let user = network::deserialize_prekey_bundle(&bundle_data)?;
    Ok(user)
}

fn chat_loop(session: Session, mut stream: TcpStream) -> Result<()> {
    let stream_clone = stream.try_clone()?;
    let session = Arc::new(Mutex::new(session));
    let session_clone = Arc::clone(&session);

    // Spawn receiving thread
    let receive_handle = thread::spawn(move || {
        let mut stream = stream_clone;
        loop {
            match network::receive_message(&mut stream) {
                Ok(msg_data) => {
                    match network::deserialize_ratchet_message(&msg_data) {
                        Ok(msg) => {
                            let mut sess = session_clone.lock().unwrap();
                            match sess.receive(msg) {
                                Ok(plaintext_bytes) => {
                                    match messages::deserialize_message(&plaintext_bytes) {
                                        Ok(messages::MessageType::Text(text)) => {
                                            // Clear current line and print message
                                            print!("\r\x1b[K");  // \r moves to start, \x1b[K clears line
                                            println!("Peer: {}", text);
                                            print!("You: ");
                                            io::stdout().flush().unwrap();
                                        }
                                        Ok(messages::MessageType::File { filename, data }) => {
                                            let save_path = format!("received_{}", filename);
                                            print!("\r\x1b[K");
                                            match std::fs::write(&save_path, data) {
                                                Ok(_) => {
                                                    println!("Received file: {} -> {}", filename, save_path);
                                                }
                                                Err(e) => {
                                                    eprintln!("Failed to save file: {}", e);
                                                }
                                            }
                                            print!("You: ");
                                            io::stdout().flush().unwrap();
                                        }
                                        Err(e) => {
                                            print!("\r\x1b[K");
                                            eprintln!("Failed to parse message: {}", e);
                                            print!("You: ");
                                            io::stdout().flush().unwrap();
                                        }
                                    }
                                }
                                Err(e) => {
                                    print!("\r\x1b[K");
                                    eprintln!("Failed to decrypt message: {}", e);
                                    print!("You: ");
                                    io::stdout().flush().unwrap();
                                }
                            }
                        }
                        Err(e) => {
                            print!("\r\x1b[K");
                            eprintln!("Failed to deserialize message: {}", e);
                            print!("You: ");
                            io::stdout().flush().unwrap();
                        }
                    }
                }
                Err(_) => {
                    print!("\r\x1b[K");
                    println!("Connection closed by peer.");
                    std::process::exit(0);
                }
            }
        }
    });

    // Main sending loop
    let stdin = io::stdin();
    print!("You: ");
    io::stdout().flush()?;

    for line in stdin.lock().lines() {
        let line = line?;
        if line.trim().is_empty() {
            print!("You: ");
            io::stdout().flush()?;
            continue;
        }

        // Parse input to detect file transfer
        match messages::parse_input(&line) {
            Ok(messages::MessageType::Text(text)) => {
                // Send text message
                let msg_bytes = messages::serialize_message(&messages::MessageType::Text(text));
                let mut sess = session.lock().unwrap();
                match sess.send_bytes(&msg_bytes) {
                    Ok(msg) => {
                        drop(sess); // Release lock before IO
                        let msg_data = network::serialize_ratchet_message(&msg);
                        if let Err(e) = network::send_message(&mut stream, &msg_data) {
                            eprintln!("Failed to send message: {}", e);
                            break;
                        }
                    }
                    Err(e) => {
                        eprintln!("Failed to encrypt message: {}", e);
                    }
                }
            }
            Ok(messages::MessageType::File { filename, data }) => {
                // Send file
                println!("Sending file: {} ({} bytes)", filename, data.len());
                let msg_bytes = messages::serialize_message(&messages::MessageType::File {
                    filename: filename.clone(),
                    data,
                });
                let mut sess = session.lock().unwrap();
                match sess.send_bytes(&msg_bytes) {
                    Ok(msg) => {
                        drop(sess); // Release lock before IO
                        let msg_data = network::serialize_ratchet_message(&msg);
                        if let Err(e) = network::send_message(&mut stream, &msg_data) {
                            eprintln!("Failed to send file: {}", e);
                            break;
                        }
                        println!("File sent: {}", filename);
                    }
                    Err(e) => {
                        eprintln!("Failed to encrypt file: {}", e);
                    }
                }
            }
            Err(e) => {
                eprintln!("Error: {}", e);
            }
        }

        print!("\nYou: ");
        io::stdout().flush()?;
    }

    receive_handle.join().unwrap();

    Ok(())
}
