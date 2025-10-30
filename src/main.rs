use anyhow::{Context, Result};
use crossterm::{
    event::{self, Event, KeyCode, KeyModifiers},
    terminal,
};
use pineapple::{messages, network, pqxdh, Session};
use std::{
    env,
    io::{self, Write},
    net::{TcpListener, TcpStream},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    thread,
};

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
            run_alice(port)?
        }
        "connect" => {
            if args.len() < 3 {
                eprintln!("Usage: {} connect <ip:port>", args[0]);
                std::process::exit(1);
            }
            let address = &args[2];
            run_bob(address)?
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

    let (mut stream, addr) = listener
        .accept()
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
    println!("Performing handshake...");

    let alice = pqxdh::User::new();
    send_public_keys(&mut stream, &alice)?;

    let mut bob = receive_public_keys(&mut stream)?;

    let (session, init_message) = Session::new_initiator(&alice, &mut bob)?;

    network::send_message(
        &mut stream,
        &network::serialize_pqxdh_init_message(&init_message),
    )?;

    println!("Session established!");
    println!("Type your message and press Enter.");
    println!("To send a file, type !path/to/file.txt");
    println!("Press Ctrl+L to clear screen. Press Ctrl+C to exit.");

    chat_loop(session, stream)?;

    Ok(())
}

fn run_bob(address: &str) -> Result<()> {
    println!("pineapple");
    println!("Connecting to {}...", address);

    let mut stream = TcpStream::connect(address)
        .context("Failed to connect to peer")?;

    println!("Connected!");
    println!("Performing handshake...");

    let mut bob = pqxdh::User::new();

    let alice = receive_public_keys(&mut stream)?;
    send_public_keys(&mut stream, &bob)?;

    let init_message_data = network::receive_message(&mut stream)?;
    let init_message = network::deserialize_pqxdh_init_message(&init_message_data)?;

    let session = Session::new_responder(&mut bob, &init_message)?;

    println!("Session established!");
    println!("Type your message and press Enter.");
    println!("To send a file, type !path/to/file.txt");
    println!("Press Ctrl+L to clear screen. Press Ctrl+C to exit.");

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
    let input_buffer = Arc::new(Mutex::new(String::new()));
    let input_buffer_clone = Arc::clone(&input_buffer);
    let running = Arc::new(AtomicBool::new(true));
    let running_clone = Arc::clone(&running);

    terminal::enable_raw_mode()?;

    let receive_handle = thread::spawn(move || {
        let mut stream = stream_clone;

        loop {
            if !running_clone.load(Ordering::SeqCst) {
                break;
            }

            match network::receive_message(&mut stream) {
                Ok(msg_data) => {
                    if msg_data == b"\x1B[2J\x1B[H" {
                        print!("\x1B[2J\x1B[H");
                        let buf = input_buffer_clone.lock().unwrap();
                        print!("You: {}", *buf);
                        io::stdout().flush().unwrap();
                        continue;
                    }

                    match network::deserialize_ratchet_message(&msg_data) {
                        Ok(msg) => {
                            let mut sess = session_clone.lock().unwrap();

                            match sess.receive(msg) {
                                Ok(plaintext_bytes) => {
                                    match messages::deserialize_message(&plaintext_bytes) {
                                        Ok(messages::MessageType::Text(text)) => {
                                            let buf = input_buffer_clone.lock().unwrap();
                                            print!("\r\x1B[K");
                                            println!("Peer: {}", text);
                                            print!("You: {}", *buf);
                                            io::stdout().flush().unwrap();
                                        }
                                        Ok(messages::MessageType::File { filename, data }) => {
                                            let save_path = format!("received_{}", filename);
                                            let buf = input_buffer_clone.lock().unwrap();
                                            print!("\r\x1B[K");

                                            match std::fs::write(&save_path, data) {
                                                Ok(_) => {
                                                    println!(
                                                        "Received file - {} -> {}",
                                                        filename,
                                                        save_path,
                                                    );
                                                }
                                                Err(e) => {
                                                    eprintln!("Failed to save file: {}", e);
                                                }
                                            }

                                            print!("You: {}", *buf);
                                            io::stdout().flush().unwrap();
                                        }
                                        Err(e) => {
                                            let buf = input_buffer_clone.lock().unwrap();
                                            print!("\r\x1B[K");
                                            eprintln!("Failed to parse message: {}", e);
                                            print!("You: {}", *buf);
                                            io::stdout().flush().unwrap();
                                        }
                                    }
                                }
                                Err(e) => {
                                    let buf = input_buffer_clone.lock().unwrap();
                                    print!("\r\x1B[K");
                                    eprintln!("Failed to decrypt message: {}", e);
                                    print!("You: {}", *buf);
                                    io::stdout().flush().unwrap();
                                }
                            }
                        }
                        Err(e) => {
                            let buf = input_buffer_clone.lock().unwrap();
                            print!("\r\x1B[K");
                            eprintln!("Failed to deserialize message: {}", e);
                            print!("You: {}", *buf);
                            io::stdout().flush().unwrap();
                        }
                    }
                }
                Err(_) => {
                    print!("\r\x1B[K");
                    println!("Connection closed by peer.");
                    terminal::disable_raw_mode().unwrap();
                    std::process::exit(0);
                }
            }
        }
    });

    print!("You: ");
    io::stdout().flush()?;

    loop {
        if event::poll(std::time::Duration::from_millis(100))? {
            if let Event::Key(k) = event::read()? {
                let mut buf = input_buffer.lock().unwrap();

                match (k.code, k.modifiers) {
                    (KeyCode::Char('c'), KeyModifiers::CONTROL) => {
                        print!("\r\n");
                        running.store(false, Ordering::SeqCst);
                        terminal::disable_raw_mode()?;
                        std::process::exit(0);
                    }
                    (KeyCode::Char('l'), KeyModifiers::CONTROL) => {
                        let clear_msg = b"\x1B[2J\x1B[H";
                        if network::send_message(&mut stream, clear_msg).is_ok() {
                            print!("\x1B[2J\x1B[H");
                            buf.clear();
                            print!("You: ");
                            io::stdout().flush()?;
                        }
                    }
                    (KeyCode::Enter, _) => {
                        let line = buf.clone();
                        buf.clear();

                        if !line.trim().is_empty() {
                            match messages::parse_input(&line) {
                                Ok(messages::MessageType::Text(text)) => {
                                    print!("\r\x1B[K");
                                    println!("You: {}", text);

                                    let msg_bytes = messages::serialize_message(
                                        &messages::MessageType::Text(text),
                                    );
                                    let mut sess = session.lock().unwrap();

                                    match sess.send_bytes(&msg_bytes) {
                                        Ok(msg) => {
                                            drop(sess);
                                            let msg_data =
                                                network::serialize_ratchet_message(&msg);

                                            if let Err(e) = network::send_message(
                                                &mut stream,
                                                &msg_data,
                                            ) {
                                                eprintln!("Failed to send message: {}", e);
                                                break Ok(());
                                            }
                                        }
                                        Err(e) => {
                                            eprintln!("Failed to encrypt message: {}", e);
                                        }
                                    }
                                }
                                Ok(messages::MessageType::File { filename, data }) => {
                                    print!("\r\x1B[K");
                                    println!(
                                        "Sending file: {} ({} bytes)",
                                        filename,
                                        data.len(),
                                    );

                                    let msg_bytes = messages::serialize_message(
                                        &messages::MessageType::File {
                                            filename: filename.clone(),
                                            data,
                                        },
                                    );
                                    let mut sess = session.lock().unwrap();

                                    match sess.send_bytes(&msg_bytes) {
                                        Ok(msg) => {
                                            drop(sess);
                                            let msg_data =
                                                network::serialize_ratchet_message(&msg);

                                            if let Err(e) = network::send_message(
                                                &mut stream,
                                                &msg_data,
                                            ) {
                                                eprintln!("Failed to send file: {}", e);
                                                break Ok(());
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
                        }

                        print!("You: ");
                        io::stdout().flush()?;
                    }
                    (KeyCode::Backspace, _) => {
                        if !buf.is_empty() {
                            buf.pop();
                            print!("\r\x1B[KYou: {}", *buf);
                            io::stdout().flush()?;
                        }
                    }
                    (KeyCode::Char(c), _) => {
                        buf.push(c);
                        print!("{}", c);
                        io::stdout().flush()?;
                    }
                    _ => {}
                }
            }
        }
    }
}

